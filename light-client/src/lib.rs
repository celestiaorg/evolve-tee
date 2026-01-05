use std::{collections::HashMap, sync::Arc};

use alloy::primitives::FixedBytes;
use alloy_provider::{Provider, fillers::FillProvider};
use anyhow::{Context, Result, anyhow};
use celestia_rpc::{BlobClient, HeaderClient, ShareClient};

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
pub const BATCH_ELF: &[u8] = include_bytes!("../../ev-batch-elf");

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

async fn build_block_input(
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
async fn get_light_block(client: &TendermintHttpClient, height: u64) -> Result<LightBlock> {
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

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use celestia_grpc_client::{CelestiaIsmClient, QueryIsmRequest, types::ClientConfig};
    use dstack_verifier::Attestation;
    use ev_prover::{config::Config, prover::chain::ChainContext};
    use ev_zkevm_types::programs::block::{BatchExecInput, State};
    use serde::Deserialize;
    use sp1_sdk::{HashableKey, ProverClient, SP1Stdin};
    use types::Inputs;

    #[derive(Deserialize)]
    struct QuoteReport {
        quote: String,
        event_log: String,
        report_data: String,
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn test_compute_evolve_state_root() {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .map_err(|_| anyhow::anyhow!("Failed to install default crypto provider"))
            .unwrap();

        dotenvy::dotenv().ok();

        let ism_client = CelestiaIsmClient::new(ClientConfig::from_env().unwrap())
            .await
            .unwrap();
        let chain_context = ChainContext::from_config(Config::default(), Arc::new(ism_client))
            .await
            .unwrap();

        // use local tendermint rpc hardcoded
        let tendermint_client = TendermintHttpClient::new("http://localhost:26657")
            .context("Failed to create Tendermint RPC client")
            .unwrap();

        let resp = chain_context
            .ism_client()
            .ism(QueryIsmRequest {
                id: chain_context.ism_id().to_string(),
            })
            .await
            .unwrap();
        let ism = resp.ism.ok_or_else(|| anyhow!("ZKISM not found")).unwrap();
        let state: State = bincode::deserialize(&ism.state).unwrap();
        // get inputs, pass trusted state to circuit, output new (mutated) state, ::execute() instead of ::prove()
        // todo: address overhead by using a non-succinct RSP (post-POC optimization, requires alignment with evolve-zkevm)
        let trusted_celestia_height = state.celestia_height;
        let mut trusted_height = state.height;
        let mut trusted_root = FixedBytes::from_slice(&state.state_root);
        let celestia_head = chain_context
            .celestia_client()
            .header_local_head()
            .await
            .unwrap()
            .height()
            .value();
        let mut block_inputs: Vec<BlockExecInput> = Vec::new();
        for block_number in trusted_celestia_height + 1..=celestia_head {
            let input = build_block_input(
                chain_context.clone(),
                block_number,
                &mut trusted_height,
                &mut trusted_root,
            )
            .await
            .unwrap();
            block_inputs.push(input);
        }

        // get light blocks
        let trusted_light_block = get_light_block(&tendermint_client, trusted_celestia_height)
            .await
            .unwrap();
        let new_light_block = get_light_block(&tendermint_client, celestia_head)
            .await
            .unwrap();
        let trusted_light_block_raw = serde_cbor::to_vec(&trusted_light_block).unwrap();
        let new_light_block_raw = serde_cbor::to_vec(&new_light_block).unwrap();
        let inputs = BatchExecInput {
            blocks: block_inputs,
            trusted_light_block_raw,
            new_light_block_raw,
        };
        let sp1_client = ProverClient::from_env();
        let mut stdin = SP1Stdin::new();
        stdin.write(&inputs);
        let (_output, report) = sp1_client.execute(BATCH_ELF, &stdin).run().unwrap();
        println!("Execution cycles: {}", report.total_instruction_count());

        // todo: run the circuit in the TEE, attest to the output and generate a ZKP of the verification with
        // valid state transition output for the ZKISM to consume
    }

    #[tokio::test]
    async fn test_verify_quote() {
        // Read the quote report from fixtures
        let fixture_path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/quote-report.json");
        let json_content =
            std::fs::read_to_string(fixture_path).expect("Failed to read fixture file");
        let report: QuoteReport =
            serde_json::from_str(&json_content).expect("Failed to parse JSON");

        // Decode the hex-encoded quote
        let quote = hex::decode(&report.quote).expect("Failed to decode quote hex");
        let event_log = report.event_log.as_bytes();

        // Create attestation from quote and event log
        let attestation = Attestation::new(quote.clone(), event_log.to_vec())
            .expect("Failed to create attestation");

        // Decode the report data from the attestation
        let report_data = attestation
            .decode_report_data()
            .expect("Failed to decode report data");

        let collateral = dcap_qvl::collateral::get_collateral(
            "https://pccs.phala.network/sgx/certification/v4/",
            &quote,
        )
        .await
        .expect("Failed to get collateral");

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to get current time")
            .as_secs();

        let verified_attestation = attestation
            .clone()
            .verify_with_collateral(&report_data, collateral, now)
            .expect("Failed to verify collateral");

        // Decode app info
        match verified_attestation.decode_app_info(false) {
            Ok(info) => {
                println!("Device ID: {}", hex::encode(info.device_id));
            }
            Err(e) => {
                panic!("Failed to decode app info: {}", e);
            }
        };
    }

    #[tokio::test]
    async fn test_generate_proof() {
        let fixture_path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/quote-report.json");
        let json_content =
            std::fs::read_to_string(fixture_path).expect("Failed to read fixture file");
        let report: QuoteReport =
            serde_json::from_str(&json_content).expect("Failed to parse JSON");

        // Decode the hex-encoded quote
        let quote = hex::decode(&report.quote).expect("Failed to decode quote hex");
        let event_log = report.event_log.as_bytes();

        let collateral = dcap_qvl::collateral::get_collateral(
            "https://pccs.phala.network/sgx/certification/v4/",
            &quote,
        )
        .await
        .expect("Failed to get collateral");

        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Failed to get current time")
            .as_secs();
        let inputs: Inputs = Inputs {
            quote,
            event_log: event_log.to_vec(),
            report_data: report.report_data.as_bytes().to_vec(),
            collateral: collateral,
            now,
        };

        let prover_client = ProverClient::from_env();
        let (pk, _vk) = prover_client.setup(CIRCUIT_ELF);
        let mut stdin = SP1Stdin::new();
        stdin.write(&inputs);
        let proof = prover_client.prove(&pk, &stdin).compressed().run().unwrap();
        println!("Proof generated successfully");
        println!("Public values: {:?}", proof.public_values);
    }
}
