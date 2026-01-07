use std::{collections::HashMap, sync::Arc};

use alloy::primitives::FixedBytes;
use alloy_provider::{Provider, fillers::FillProvider};
use anyhow::{Context, Result, anyhow};
use celestia_rpc::{BlobClient, HeaderClient, ShareClient};
use serde::Deserialize;

use celestia_types::{Blob, Height, ValidatorSet, nmt::NamespaceProof};
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
    let proofs: Vec<NamespaceProof> = namespace_data.rows.into_iter().map(|r| r.proof).collect();

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
    let mut executor_inputs: Vec<EthClientExecutorInput> = Vec::new();
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
    if last_height > 0 {
        let block = chain_context
            .evm_provider()
            .get_block_by_number(last_height.into())
            .await?
            .ok_or_else(|| anyhow!("Block {last_height} not found"))?;

        *trusted_height = last_height;
        *trusted_root = block.header.state_root;
    }

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
