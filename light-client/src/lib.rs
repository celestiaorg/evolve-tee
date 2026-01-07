use std::{collections::HashMap, sync::Arc};

use alloy::primitives::FixedBytes;
use alloy_provider::{Provider, fillers::FillProvider};
use anyhow::{Context, Result, anyhow};
use celestia_rpc::{BlobClient, HeaderClient, ShareClient};
use serde::Deserialize;

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
/// then fetches blobs and proofs sequentially.
/// This reduces the number of RPC calls from 3N to 2N+1 (1 header range + N blobs + N proofs).
pub async fn prefetch_celestia_data_batch(
    chain_context: Arc<ChainContext>,
    from_height: u64,
    to_height: u64,
) -> Result<Vec<PrefetchedCelestiaData>> {

    let num_blocks = to_height - from_height + 1;
    let prefetch_start = std::time::Instant::now();
    println!(
        "Prefetching Celestia data from height {} to {} ({} blocks)",
        from_height, to_height, num_blocks
    );

    // First, get the starting header
    let header_start = std::time::Instant::now();
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
    let header_duration = header_start.elapsed();
    println!(
        "  Headers fetched in {:.2}s ({} blocks)",
        header_duration.as_secs_f64(),
        num_blocks
    );

    // Create a map of height -> header for easy lookup
    let header_map: HashMap<u64, ExtendedHeader> = headers
        .into_iter()
        .map(|h| (h.height().value(), h))
        .collect();

    // Fetch blobs and proofs sequentially
    let blobs_start = std::time::Instant::now();
    let heights: Vec<u64> = (from_height..=to_height).collect();
    let mut prefetched: Vec<PrefetchedCelestiaData> = Vec::new();

    for height in heights {
        let header = header_map.get(&height).cloned()
            .ok_or_else(|| anyhow!("Header not found for height {}", height))?;
        let namespace = chain_context.namespace();

        // Fetch blobs
        let blobs: Vec<Blob> = chain_context
            .celestia_client()
            .blob_get_all(height, &[namespace])
            .await?
            .unwrap_or_default();

        // Fetch namespace data for proofs
        let namespace_data = chain_context
            .celestia_client()
            .share_get_namespace_data(&header, namespace)
            .await?;
        let proofs: Vec<NamespaceProof> =
            namespace_data.rows.into_iter().map(|r| r.proof).collect();

        prefetched.push(PrefetchedCelestiaData {
            height,
            blobs,
            extended_header: header,
            proofs,
        });
    }
    let blobs_duration = blobs_start.elapsed();
    println!(
        "  Blobs and proofs fetched in {:.2}s ({} blocks, {:.2}ms per block)",
        blobs_duration.as_secs_f64(),
        num_blocks,
        blobs_duration.as_millis() as f64 / num_blocks as f64
    );

    let prefetch_duration = prefetch_start.elapsed();
    println!(
        "  Total prefetch completed in {:.2}s ({:.2}ms per block)",
        prefetch_duration.as_secs_f64(),
        prefetch_duration.as_millis() as f64 / num_blocks as f64
    );

    Ok(prefetched)
}

/// Build block input from prefetched Celestia data. This handles the sequential
/// trusted state updates and must be called in order.
/// Returns (BlockExecInput, executor_duration) where executor_duration is the time spent in host executor.
pub async fn build_block_input_from_prefetched(
    chain_context: Arc<ChainContext>,
    prefetched: PrefetchedCelestiaData,
    trusted_height: &mut u64,
    trusted_root: &mut FixedBytes<32>,
) -> Result<(BlockExecInput, std::time::Duration)> {
    #[allow(unused_variables)]
    let PrefetchedCelestiaData {
        height: _,
        blobs,
        extended_header,
        proofs,
    } = prefetched;

    if blobs.is_empty() {
        return Ok((
            BlockExecInput {
                header_raw: serde_cbor::to_vec(&extended_header.header)?,
                dah: extended_header.dah,
                blobs_raw: serde_cbor::to_vec(&blobs)?,
                pub_key: chain_context.pub_key_bytes(),
                namespace: chain_context.namespace(),
                proofs,
                executor_inputs: vec![],
                trusted_height: *trusted_height,
                trusted_root: *trusted_root,
            },
            std::time::Duration::ZERO,
        ));
    }

    // Process blobs to extract executor inputs
    // Match the reference implementation logic exactly

    // First pass: extract heights from blobs
    let mut heights_to_fetch = Vec::new();
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
        heights_to_fetch.push(height);
    }

    let last_height = heights_to_fetch.last().copied().unwrap_or(0);

    // Second pass: fetch executor inputs sequentially
    let executor_start = std::time::Instant::now();
    let mut executor_inputs: Vec<EthClientExecutorInput> = Vec::new();

    for height in heights_to_fetch {
        let chain_spec = chain_context.chain_spec();
        let genesis = chain_context.genesis();
        let provider = chain_context.evm_provider();
        let (input, _) = generate_executor_input(chain_spec, genesis, provider, height).await?;
        executor_inputs.push(input);
    }

    let executor_wall_time = executor_start.elapsed();

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
    // Only update if we actually processed blocks (last_height > 0)
    if last_height > 0 {
        let block = chain_context
            .evm_provider()
            .get_block_by_number(last_height.into())
            .await?
            .ok_or_else(|| anyhow!("Block {last_height} not found"))?;

        *trusted_height = last_height;
        *trusted_root = block.header.state_root;
    }

    Ok((input, executor_wall_time))
}

async fn generate_executor_input(
    chain_spec: Arc<ChainSpec>,
    genesis: Genesis,
    provider: DefaultProvider,
    block_number: u64,
) -> Result<(EthClientExecutorInput, std::time::Duration)> {
    let host_executor = EthHostExecutor::eth(chain_spec, None);
    let rpc_db = RpcDb::new(provider.clone(), block_number.saturating_sub(1));

    let executor_input = host_executor
        .execute(block_number, &rpc_db, &provider, genesis, None, false)
        .await?;

    // Note: We can't easily measure raw execution time vs RPC time from here
    // because it's all inside host_executor.execute(). The RpcDb fetches state
    // on-demand during execution, so they're interleaved.
    Ok((executor_input, std::time::Duration::ZERO))
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

/// Response from the middleware service for block input queries.
#[derive(Deserialize)]
struct QueryBlockInputsResponse {
    success: bool,
    block_inputs: Option<Vec<String>>,
    error: Option<String>,
    timing: Option<MiddlewareTiming>,
}

#[derive(Deserialize, Clone, Debug)]
pub struct MiddlewareTiming {
    pub total_time_seconds: f64,
}

/// Fetches block inputs from the middleware service.
///
/// This function calls the middleware's `/query_block_inputs` endpoint which
/// handles all the expensive RPC calls and returns pre-built BlockExecInput data.
/// This reduces network overhead from O(n) RPC calls to O(1) HTTP request,
/// which is critical in TEE environments where network I/O is expensive.
///
/// # Arguments
///
/// * `middleware_url` - The base URL of the middleware service (e.g., "http://localhost:9091")
/// * `from_height` - Starting Celestia height (inclusive)
/// * `to_height` - Ending Celestia height (inclusive)
/// * `trusted_height` - The trusted EVM block height
/// * `trusted_root` - The trusted EVM state root as a hex string (without 0x prefix)
///
/// # Returns
///
/// A tuple of (`BlockExecInput` vector, optional `MiddlewareTiming`).
/// The vector contains inputs in sequential order from `from_height` to `to_height`.
pub async fn fetch_block_inputs_from_middleware(
    middleware_url: &str,
    from_height: u64,
    to_height: u64,
    trusted_height: u64,
    trusted_root: &str,
) -> Result<(Vec<BlockExecInput>, Option<MiddlewareTiming>)> {
    let url = format!(
        "{}/query_block_inputs?from_height={}&to_height={}&trusted_height={}&trusted_root={}",
        middleware_url, from_height, to_height, trusted_height, trusted_root
    );

    let client = reqwest::Client::new();
    let response: QueryBlockInputsResponse = client
        .get(&url)
        .send()
        .await
        .map_err(|e| anyhow!("Failed to send request to middleware: {}", e))?
        .json()
        .await
        .map_err(|e| anyhow!("Failed to parse middleware response: {}", e))?;

    if !response.success {
        return Err(anyhow!(
            "Middleware returned error: {}",
            response
                .error
                .unwrap_or_else(|| "Unknown error".to_string())
        ));
    }

    let block_inputs_hex = response
        .block_inputs
        .ok_or_else(|| anyhow!("No block inputs in response"))?;

    // Deserialize block inputs from hex
    let mut block_inputs = Vec::new();
    for hex_str in block_inputs_hex {
        let bytes = hex::decode(&hex_str)
            .map_err(|e| anyhow!("Failed to decode block input hex: {}", e))?;
        let input: BlockExecInput = bincode::deserialize(&bytes)
            .map_err(|e| anyhow!("Failed to deserialize block input: {}", e))?;
        block_inputs.push(input);
    }

    Ok((block_inputs, response.timing))
}
