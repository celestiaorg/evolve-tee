use std::{collections::HashMap, sync::Arc};

use alloy::primitives::FixedBytes;
use alloy_provider::{Provider, fillers::FillProvider};
use anyhow::{Context, Result, anyhow};
use celestia_rpc::{BlobClient, HeaderClient, ShareClient};

use celestia_types::{Blob, ExtendedHeader, Height, ValidatorSet, nmt::NamespaceProof};
use ev_prover::prover::chain::ChainContext;
use ev_types::v1::SignedData;
use ev_zkevm_types::programs::block::{BlockExecInput, BlockRangeExecOutput, BlockVerifier};
use prost::Message;
use reth_chainspec::ChainSpec;
use rsp_client_executor::io::EthClientExecutorInput;
use rsp_host_executor::EthHostExecutor;
use rsp_primitives::genesis::Genesis;
use rsp_rpc_db::RpcDb;
use sp1_sdk::include_elf;
use tendermint_light_client_verifier::types::{LightBlock, SignedHeader};
use tendermint_rpc::{Client as TendermintClient, HttpClient as TendermintHttpClient};

pub type DefaultProvider = FillProvider<
    alloy_provider::fillers::JoinFill<
        alloy_provider::Identity,
        alloy_provider::fillers::JoinFill<
            alloy_provider::fillers::GasFiller,
            alloy_provider::fillers::JoinFill<
                alloy_provider::fillers::BlobGasFiller,
                alloy_provider::fillers::JoinFill<
                    alloy_provider::fillers::NonceFiller,
                    alloy_provider::fillers::ChainIdFiller,
                >,
            >,
        >,
    >,
    alloy_provider::RootProvider,
>;

pub const CIRCUIT_ELF: &[u8] = include_elf!("circuit");
pub const BATCH_ELF: &[u8] = include_bytes!("../fixtures/ev-batch-elf");

pub async fn verify_blocks(
    inputs: Vec<BlockExecInput>,
    trusted_light_block: LightBlock,
    new_light_block: LightBlock,
) -> Result<BlockRangeExecOutput> {
    let verifier = BlockVerifier {};
    Ok(verifier
        .verify_range(inputs, trusted_light_block, new_light_block)
        .map_err(|e| anyhow!("{e}"))?)
}

/// Prefetched Celestia data that can be fetched in parallel
pub struct PrefetchedCelestiaData {
    pub height: u64,
    pub blobs: Vec<Blob>,
    pub extended_header: ExtendedHeader,
    pub proofs: Vec<NamespaceProof>,
}

/// Prefetch Celestia data for a given height. This can be called in parallel
/// for multiple heights since it only performs network fetches.
pub async fn prefetch_celestia_data(
    chain_context: Arc<ChainContext>,
    height: u64,
) -> Result<PrefetchedCelestiaData> {
    let blobs: Vec<Blob> = chain_context
        .celestia_client()
        .blob_get_all(height, &[chain_context.namespace()])
        .await?
        .unwrap_or_default();
    let extended_header = chain_context
        .celestia_client()
        .header_get_by_height(height)
        .await?;
    let namespace_data = chain_context
        .celestia_client()
        .share_get_namespace_data(&extended_header, chain_context.namespace())
        .await?;
    let proofs: Vec<NamespaceProof> = namespace_data.rows.into_iter().map(|r| r.proof).collect();

    Ok(PrefetchedCelestiaData {
        height,
        blobs,
        extended_header,
        proofs,
    })
}

/// Batch prefetch Celestia data for a range of heights.
/// Uses header_get_range_by_height to fetch all headers in one request,
/// then fetches blobs and proofs in parallel.
/// This reduces the number of RPC calls from 3N to 2N+1 (1 header range + N blobs + N proofs).
pub async fn prefetch_celestia_data_batch(
    chain_context: Arc<ChainContext>,
    from_height: u64,
    to_height: u64,
) -> Result<Vec<PrefetchedCelestiaData>> {
    use futures::future::try_join_all;

    // First, get the starting header
    let from_header = chain_context
        .celestia_client()
        .header_get_by_height(from_height)
        .await?;

    // Fetch all headers in one request (instead of N individual requests)
    // Note: header_get_range_by_height returns headers from (from.height + 1) to (to - 1),
    let headers: Vec<ExtendedHeader> = if from_height == to_height {
        vec![from_header]
    } else {
        let mut headers = vec![from_header.clone()];
        let range_headers = chain_context
            .celestia_client()
            .header_get_range_by_height(&from_header, to_height + 1)
            .await?;
        headers.extend(range_headers);
        headers
    };

    // Create a map of height -> header for easy lookup
    let header_map: HashMap<u64, ExtendedHeader> = headers
        .into_iter()
        .map(|h| (h.height().value(), h))
        .collect();

    // Fetch blobs and proofs in parallel for each height
    let heights: Vec<u64> = (from_height..=to_height).collect();
    let fetch_futures = heights.into_iter().map(|height| {
        let ctx = chain_context.clone();
        let header = header_map.get(&height).cloned();
        async move {
            let header = header.ok_or_else(|| anyhow!("Header not found for height {}", height))?;
            let namespace = ctx.namespace();

            // Fetch blobs
            let blobs: Vec<Blob> = ctx
                .celestia_client()
                .blob_get_all(height, &[namespace])
                .await?
                .unwrap_or_default();

            // Fetch namespace data for proofs
            let namespace_data = ctx
                .celestia_client()
                .share_get_namespace_data(&header, namespace)
                .await?;
            let proofs: Vec<NamespaceProof> =
                namespace_data.rows.into_iter().map(|r| r.proof).collect();

            Ok::<_, anyhow::Error>(PrefetchedCelestiaData {
                height,
                blobs,
                extended_header: header,
                proofs,
            })
        }
    });

    try_join_all(fetch_futures).await
}

/// Build block input from prefetched Celestia data. This handles the sequential
/// trusted state updates and must be called in order.
pub async fn build_block_input_from_prefetched(
    chain_context: Arc<ChainContext>,
    prefetched: PrefetchedCelestiaData,
    trusted_height: &mut u64,
    trusted_root: &mut FixedBytes<32>,
) -> Result<BlockExecInput> {
    use futures::future::try_join_all;

    let PrefetchedCelestiaData {
        height: _,
        blobs,
        extended_header,
        proofs,
    } = prefetched;

    if blobs.is_empty() {
        return Ok(BlockExecInput {
            header_raw: serde_cbor::to_vec(&extended_header.header)?,
            dah: extended_header.dah,
            blobs_raw: serde_cbor::to_vec(&blobs)?,
            pub_key: chain_context.pub_key_bytes(),
            namespace: chain_context.namespace(),
            proofs,
            executor_inputs: vec![],
            trusted_height: *trusted_height,
            trusted_root: *trusted_root,
        });
    }

    // First pass: Extract heights from all blobs
    let mut heights = Vec::new();
    let mut last_height = 0;
    for blob in blobs.as_slice() {
        let signed_data = match SignedData::decode(blob.data.as_slice()) {
            Ok(data) => data,
            Err(_) => continue,
        };
        let data = signed_data.data.ok_or_else(|| anyhow!("Data not found"))?;
        let height = data
            .metadata
            .ok_or_else(|| anyhow!("Metadata not found"))?
            .height;
        last_height = height;
        heights.push(height);
    }

    // Second pass: Generate all executor inputs in parallel
    // This allows all RPC calls to happen concurrently instead of sequentially
    let executor_futures = heights.into_iter().map(|height| {
        let chain_spec = chain_context.chain_spec();
        let genesis = chain_context.genesis();
        let provider = chain_context.evm_provider();
        async move { generate_executor_input(chain_spec, genesis, provider, height).await }
    });

    let executor_inputs = try_join_all(executor_futures).await?;

    // Construct the block execution input
    let input = BlockExecInput {
        header_raw: serde_cbor::to_vec(&extended_header.header)?,
        dah: extended_header.dah,
        blobs_raw: serde_cbor::to_vec(&blobs)?,
        pub_key: chain_context.pub_key_bytes(),
        namespace: chain_context.namespace(),
        proofs,
        executor_inputs: executor_inputs.clone(),
        trusted_height: *trusted_height,
        trusted_root: *trusted_root,
    };

    // Update trusted state based on the last EVM block processed
    let block = chain_context
        .evm_provider()
        .get_block_by_number(last_height.into())
        .await?
        .ok_or_else(|| anyhow!("Block {last_height} not found"))?;

    *trusted_height = last_height;
    *trusted_root = block.header.state_root;

    Ok(input)
}

pub async fn build_block_input(
    chain_context: Arc<ChainContext>,
    height: u64,
    trusted_height: &mut u64,
    trusted_root: &mut FixedBytes<32>,
) -> Result<BlockExecInput> {
    let blobs: Vec<Blob> = chain_context
        .celestia_client()
        .blob_get_all(height, &[chain_context.namespace()])
        .await?
        .unwrap_or_default();
    let extended_header = chain_context
        .celestia_client()
        .header_get_by_height(height)
        .await?;
    let namespace_data = chain_context
        .celestia_client()
        .share_get_namespace_data(&extended_header, chain_context.namespace())
        .await?;
    let mut proofs: Vec<NamespaceProof> = Vec::new();
    for row in namespace_data.rows {
        proofs.push(row.proof);
    }

    let mut executor_inputs: Vec<EthClientExecutorInput> = Vec::new();

    if blobs.is_empty() {
        return Ok(BlockExecInput {
            header_raw: serde_cbor::to_vec(&extended_header.header)?,
            dah: extended_header.dah,
            blobs_raw: serde_cbor::to_vec(&blobs)?,
            pub_key: chain_context.pub_key_bytes(),
            namespace: chain_context.namespace(),
            proofs,
            executor_inputs: vec![],
            trusted_height: *trusted_height,
            trusted_root: *trusted_root,
        });
    }

    // Process blobs to extract executor inputs
    let mut last_height = 0;
    for blob in blobs.as_slice() {
        let signed_data = match SignedData::decode(blob.data.as_slice()) {
            Ok(data) => data,
            Err(_) => continue,
        };
        let data = signed_data.data.ok_or_else(|| anyhow!("Data not found"))?;
        let height = data
            .metadata
            .ok_or_else(|| anyhow!("Metadata not found"))?
            .height;
        last_height = height;

        let client_executor_input = generate_executor_input(
            chain_context.chain_spec(),
            chain_context.genesis(),
            chain_context.evm_provider(),
            height,
        )
        .await?;
        executor_inputs.push(client_executor_input);
    }

    // Construct the block execution input
    let input = BlockExecInput {
        header_raw: serde_cbor::to_vec(&extended_header.header)?,
        dah: extended_header.dah,
        blobs_raw: serde_cbor::to_vec(&blobs)?,
        pub_key: chain_context.pub_key_bytes(),
        namespace: chain_context.namespace(),
        proofs,
        executor_inputs: executor_inputs.clone(),
        trusted_height: *trusted_height,
        trusted_root: *trusted_root,
    };

    // Update trusted state based on the last EVM block processed
    let block = chain_context
        .evm_provider()
        .get_block_by_number(last_height.into())
        .await?
        .ok_or_else(|| anyhow!("Block {last_height} not found"))?;

    *trusted_height = last_height;
    *trusted_root = block.header.state_root;

    Ok(input)
}

async fn generate_executor_input(
    chain_spec: Arc<ChainSpec>,
    genesis: Genesis,
    provider: DefaultProvider,
    block_number: u64,
) -> Result<EthClientExecutorInput> {
    let host_executor = EthHostExecutor::eth(chain_spec, None);
    let rpc_db = RpcDb::new(provider.clone(), block_number.saturating_sub(1));

    let executor_input = host_executor
        .execute(block_number, &rpc_db, &provider, genesis, None, false)
        .await?;

    Ok(executor_input)
}

/// Fetches a Tendermint LightBlock at the given height.
/// This is used for light client verification in the zkVM.
pub async fn get_light_block(client: &TendermintHttpClient, height: u64) -> Result<LightBlock> {
    let height = Height::try_from(height).context("invalid height")?;

    // Fetch peer ID from the node status
    let status = client
        .status()
        .await
        .context("failed to fetch node status")?;
    let peer_id = status.node_info.id;

    // Fetch commit at the given height
    let commit_response = client
        .commit(height)
        .await
        .context("failed to fetch commit")?;
    let mut signed_header = commit_response.signed_header;

    // Fetch validators at the given height
    let validators_response = client
        .validators(height, tendermint_rpc::Paging::All)
        .await
        .context("failed to fetch validators")?;
    let validators = ValidatorSet::new(validators_response.validators, None);

    // Fetch next validators (at height + 1)
    let next_height = height.increment();
    let next_validators_response = client
        .validators(next_height, tendermint_rpc::Paging::All)
        .await
        .context("failed to fetch next validators")?;
    let next_validators = ValidatorSet::new(next_validators_response.validators, None);

    // Sort signatures by validators power in descending order
    sort_signatures_by_validators_power_desc(&mut signed_header, &validators);

    Ok(LightBlock::new(
        signed_header,
        validators,
        next_validators,
        peer_id,
    ))
}

fn sort_signatures_by_validators_power_desc(
    signed_header: &mut SignedHeader,
    validators_set: &ValidatorSet,
) {
    let validator_powers: HashMap<_, _> = validators_set
        .validators()
        .iter()
        .map(|v| (v.address, v.power()))
        .collect();

    signed_header.commit.signatures.sort_by(|a, b| {
        let power_a = a
            .validator_address()
            .and_then(|addr| validator_powers.get(&addr))
            .unwrap_or(&0);
        let power_b = b
            .validator_address()
            .and_then(|addr| validator_powers.get(&addr))
            .unwrap_or(&0);
        power_b.cmp(power_a)
    });
}
