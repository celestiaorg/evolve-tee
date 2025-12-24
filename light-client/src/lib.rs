use std::sync::Arc;

use alloy::primitives::FixedBytes;
use alloy_provider::{Provider, fillers::FillProvider};
use anyhow::{Result, anyhow};
use celestia_rpc::{BlobClient, HeaderClient, ShareClient, client::Client};

use celestia_types::{
    Blob,
    nmt::{Namespace, NamespaceProof},
};
use ev_types::v1::SignedData;
use ev_zkevm_types::programs::block::{BlockExecInput, BlockRangeExecOutput, BlockVerifier};
use prost::Message;
use rsp_client_executor::io::EthClientExecutorInput;
use sp1_sdk::include_elf;
use tendermint_light_client_verifier::types::LightBlock;

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

pub async fn prepare_inputs(
    start_height: u64,
    batch_size: u64,
    namespace: Namespace,
    pubkey_bytes: Vec<u8>,
    trusted_height: u64,
    trusted_root: FixedBytes<32>,
    celestia_client: Arc<Client>,
    evm_provider: DefaultProvider,
) -> Result<()> {
    let mut current_height = trusted_height;
    let mut current_root = trusted_root;
    let mut block_inputs: Vec<BlockExecInput> = Vec::new();
    for block_number in start_height..=start_height + batch_size {
        let input = build_block_input(
            block_number,
            namespace,
            pubkey_bytes.clone(),
            &mut current_height,
            &mut current_root,
            celestia_client.clone(),
            evm_provider.clone(),
        )
        .await?;

        block_inputs.push(input);
    }
    Ok(())
}

async fn build_block_input(
    height: u64,
    namespace: Namespace,
    pubkey_bytes: Vec<u8>,
    trusted_height: &mut u64,
    trusted_root: &mut FixedBytes<32>,
    celestia_client: Arc<Client>,
    evm_provider: DefaultProvider,
) -> Result<BlockExecInput> {
    let blobs: Vec<Blob> = celestia_client
        .blob_get_all(height, &[namespace])
        .await?
        .unwrap_or_default();
    let extended_header = celestia_client.header_get_by_height(height).await?;
    let namespace_data = celestia_client
        .share_get_namespace_data(&extended_header, namespace)
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
            pub_key: pubkey_bytes,
            namespace,
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

        //let client_executor_input = self.ctx.generate_executor_input(height).await?;
        //executor_inputs.push(client_executor_input);
    }

    // Construct the block execution input
    let input = BlockExecInput {
        header_raw: serde_cbor::to_vec(&extended_header.header)?,
        dah: extended_header.dah,
        blobs_raw: serde_cbor::to_vec(&blobs)?,
        pub_key: pubkey_bytes,
        namespace,
        proofs,
        executor_inputs: executor_inputs.clone(),
        trusted_height: *trusted_height,
        trusted_root: *trusted_root,
    };

    // Update trusted state based on the last EVM block processed
    let block = evm_provider
        .get_block_by_number(last_height.into())
        .await?
        .ok_or_else(|| anyhow!("Block {last_height} not found"))?;

    *trusted_height = last_height;
    *trusted_root = block.header.state_root;

    Ok(input)
}

#[cfg(test)]
mod tests {
    use std::time::SystemTime;

    use super::*;
    use dstack_verifier::Attestation;
    use serde::Deserialize;
    use sp1_sdk::{Prover, ProverClient, SP1Stdin};
    use types::Inputs;

    #[derive(Deserialize)]
    struct QuoteReport {
        quote: String,
        event_log: String,
        report_data: String,
        vm_config: String,
    }

    #[tokio::test]
    async fn test_prepare_inputs() {
        use alloy_provider::ProviderBuilder;
        use url::Url;

        let celestia_client = Arc::new(Client::new("CELESTIA_RPC_URL", None).await.unwrap());
        let evm_provider = ProviderBuilder::new().connect_http(Url::parse("EVM_RPC_URL").unwrap());
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
        let attestation =
            Attestation::new(quote, event_log.to_vec()).expect("Failed to create attestation");

        // Decode the report data from the attestation
        let report_data = attestation
            .decode_report_data()
            .expect("Failed to decode report data");

        // Verify the attestation
        attestation
            .clone()
            .verify(
                &report_data,
                Some("https://pccs.phala.network/sgx/certification/v4/"),
            )
            .await
            .expect("Failed to verify attestation");

        // Decode app info
        match attestation.decode_app_info(false) {
            Ok(info) => {
                println!("Device ID: {}", hex::encode(info.device_id));
            }
            Err(e) => {
                panic!("Failed to decode app info: {}", e);
            }
        };
    }

    #[tokio::test]
    async fn test_verify_quote_alt() {
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
        let proof = prover_client.prove(&pk, &stdin).run().unwrap();
        println!("Proof: {}", hex::encode(proof.bytes()));
    }
}
