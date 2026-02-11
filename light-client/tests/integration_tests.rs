use std::sync::Arc;
use std::time::SystemTime;

use alloy::primitives::FixedBytes;
use anyhow::{Context, anyhow};
use celestia_grpc_client::{CelestiaIsmClient, QueryIsmRequest, types::ClientConfig};
use celestia_rpc::HeaderClient;
use ev_prover::{config::Config, prover::chain::ChainContext};
use ev_zkevm_types::programs::block::{BlockRangeExecOutput, State};
use serde::Deserialize;
use sha2::Digest;
use sp1_sdk::{ProverClient, SP1Stdin};
use tee_attestation_types::{AttestationResponse, Inputs};
use tee_light_client_lib::{
    CIRCUIT_ELF, fetch_block_inputs_from_middleware, get_light_block, verify_blocks,
};
use tendermint_rpc::HttpClient as TendermintHttpClient;

/// Represents a TEE quote report containing attestation data.
#[derive(Deserialize)]
struct QuoteReport {
    /// Hex-encoded SGX/TDX quote bytes.
    quote: String,
    /// Event log data for attestation verification.
    event_log: String,
    /// Hex-encoded output data committed to in the attestation.
    output: Option<String>,
}

/// Tests computing the Evolve state root using the middleware service.
///
/// This test fetches the current ISM state, calls the middleware to get pre-built block inputs
/// from the trusted height to the current Celestia head, and runs native block verification to
/// compute the new state. The middleware handles all expensive RPC calls (Celestia headers, blobs,
/// proofs, and EVM data) and returns the inputs in a single HTTP response.
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

    // Override default config with remote RPC endpoints
    let mut config = Config::default();
    config.rpc.celestia_rpc = "http://51.159.171.247:26658".to_string();
    config.rpc.evnode_rpc = "http://51.159.171.247:26658".to_string();
    config.rpc.evreth_rpc = "http://51.159.171.247:8545".to_string();
    config.rpc.evreth_ws = "ws://51.159.171.247:8546".to_string();
    config.pub_key = "3964a68700cf76e215626e076e76d23bd1f4c3b31184b5822fd7b4df15d5ce9a".to_string();

    let chain_context = ChainContext::from_config(config, Arc::new(ism_client))
        .await
        .unwrap();

    // use remote tendermint rpc
    let tendermint_client = TendermintHttpClient::new("http://51.159.171.247:26657")
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
    let trusted_celestia_height = state.celestia_height;
    let trusted_height = state.height;
    let trusted_root: FixedBytes<32> = FixedBytes::from_slice(&state.state_root);
    let celestia_head = chain_context
        .celestia_client()
        .header_local_head()
        .await
        .unwrap()
        .height()
        .value();

    // Get middleware endpoint from environment variable
    let middleware_url = std::env::var("MIDDLEWARE_ENDPOINT")
        .unwrap_or_else(|_| "http://51.159.171.247:9091".to_string());

    // Fetch block inputs from middleware (replaces direct prefetch/build logic)
    let (block_inputs, middleware_timing) = fetch_block_inputs_from_middleware(
        &middleware_url,
        trusted_celestia_height + 1,
        celestia_head,
        trusted_height,
        &hex::encode(trusted_root.as_slice()),
    )
    .await
    .expect("Failed to fetch block inputs from middleware");

    if let Some(timing) = middleware_timing {
        println!("Middleware timing: total={:.2}s", timing.total_time_seconds);
    }

    // get light blocks
    let trusted_light_block = get_light_block(&tendermint_client, trusted_celestia_height)
        .await
        .unwrap();
    let new_light_block = get_light_block(&tendermint_client, celestia_head)
        .await
        .unwrap();

    // Native block verification (replaces SP1 execution)
    let output = verify_blocks(block_inputs, trusted_light_block, new_light_block)
        .await
        .unwrap();

    println!("Output: {:?}", hex::encode(output.new_state.state_root));
}

/// Tests ZK proof generation for TEE attestation verification.
///
/// Loads a quote report from fixtures and generates a compressed SP1 proof
/// that the attestation is valid.
#[tokio::test]
async fn test_generate_proof() {
    let fixture_path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/quote-report.json");
    let json_content = std::fs::read_to_string(fixture_path).expect("Failed to read fixture file");
    let report: QuoteReport = serde_json::from_str(&json_content).expect("Failed to parse JSON");

    // Decode the hex-encoded quote
    let quote = hex::decode(&report.quote).expect("Failed to decode quote hex");
    let event_log = report.event_log.as_bytes();

    // Verify event log can be decoded (regression test for format compatibility)
    let decoded_events: Vec<tee_attestation_types::EventLog> =
        serde_json::from_slice(event_log).expect("Failed to decode event log JSON");
    println!("Successfully decoded {} event log entries", decoded_events.len());

    // Verify first event has expected format (hex-encoded strings)
    assert!(!decoded_events.is_empty(), "Event log should not be empty");
    let first_event = &decoded_events[0];
    assert!(
        hex::decode(&first_event.digest).is_ok(),
        "Event digest should be valid hex"
    );
    assert!(
        hex::decode(&first_event.event_payload).is_ok(),
        "Event payload should be valid hex"
    );

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

    // Decode the output if present in the fixture, otherwise use empty vec
    let output = report
        .output
        .as_ref()
        .map(|o| hex::decode(o).expect("Failed to decode output hex"))
        .unwrap_or_else(Vec::new);

    let inputs: Inputs = Inputs {
        quote,
        event_log: event_log.to_vec(),
        report_data: Vec::new(), // Not used - report_data is extracted from quote in circuit
        collateral,
        output,
        now,
    };

    let prover_client = ProverClient::from_env();
    let (pk, _vk) = prover_client.setup(CIRCUIT_ELF);
    let mut stdin = SP1Stdin::new();
    stdin.write(&inputs);
    let proof = prover_client.prove(&pk, &stdin).compressed().run().unwrap();

    // Also verify the block execution output contains the expected state root
    let block_output: BlockRangeExecOutput =
        bincode::deserialize(&proof.public_values.as_slice()).unwrap();
    assert_eq!(
        hex::encode(block_output.new_state.state_root),
        "a059811e85dd8053da9b37ab90e60d74c19f417f5691651d74128fe39270c7df",
        "New state root should match expected value"
    );
}

/// Test that fetches attestation from the TEE app and generates a proof using the circuit.
///
/// This test requires the TEE app to be running at the URL specified by TEE_APP_URL env var.
/// The test:
/// 1. Fetches attestation data (quote, event_log, output) from /attestation endpoint
/// 2. Retrieves collateral for the quote
/// 3. Constructs circuit inputs with the attested output
/// 4. Generates a ZK proof that verifies the attestation
#[tokio::test]
async fn test_attestation_proof_from_tee() {
    dotenvy::dotenv().ok();

    // Get the TEE app URL from environment or use default
    let tee_app_url =
        std::env::var("TEE_APP_URL").expect("TEE_APP_URL environment variable is not set");

    // Fetch attestation from the TEE app
    let client = reqwest::Client::new();
    let response = client
        .get(format!("{}/attestation", tee_app_url))
        .send()
        .await
        .expect("Failed to connect to TEE app");

    let attestation: AttestationResponse = response
        .json()
        .await
        .expect("Failed to parse attestation response");

    if !attestation.success {
        panic!(
            "Attestation failed at step {:?}: {:?}",
            attestation.step, attestation.error
        );
    }

    let quote_hex = attestation.quote.expect("Missing quote in response");
    let event_log_str = attestation
        .event_log
        .expect("Missing event_log in response");
    let output_hex = attestation.output.expect("Missing output in response");

    // Decode the hex-encoded values
    let quote = hex::decode(&quote_hex).expect("Failed to decode quote hex");
    let event_log = event_log_str.as_bytes();
    let output = hex::decode(&output_hex).expect("Failed to decode output hex");

    // Verify event log can be decoded (regression test for format compatibility)
    let decoded_events: Vec<tee_attestation_types::EventLog> =
        serde_json::from_slice(event_log).expect("Failed to decode event log JSON from TEE");
    println!("Successfully decoded {} event log entries from TEE", decoded_events.len());

    // Verify events have expected format (hex-encoded strings)
    assert!(!decoded_events.is_empty(), "Event log from TEE should not be empty");
    for (i, event) in decoded_events.iter().enumerate() {
        assert!(
            hex::decode(&event.digest).is_ok(),
            "Event {} digest should be valid hex", i
        );
        assert!(
            hex::decode(&event.event_payload).is_ok(),
            "Event {} payload should be valid hex", i
        );
    }

    // Get collateral for the quote
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

    // The report_data in the quote is the SHA-256 hash of the output (first 32 bytes)
    // We pass the raw output; the circuit will verify the hash matches
    let inputs: Inputs = Inputs {
        quote,
        event_log: event_log.to_vec(),
        report_data: Vec::new(), // Not used directly, extracted from quote in circuit
        collateral,
        output,
        now,
    };

    let prover_client = ProverClient::from_env();
    let (pk, vk) = prover_client.setup(CIRCUIT_ELF);

    let mut stdin = SP1Stdin::new();
    stdin.write(&inputs);

    let proof = prover_client
        .prove(&pk, &stdin)
        .groth16()
        .run()
        .expect("Failed to generate proof");

    // Verify the proof
    prover_client
        .verify(&proof, &vk)
        .expect("Failed to verify proof");
}

/// Test that verifies a pre-generated proof from test fixtures.
///
/// This test loads proof.bin, public_outputs.bin, and circuit.elf from fixtures
/// and verifies that the proof is valid for the circuit.
#[test]
fn test_verify_attestation_sp1_proof() {
    use sp1_sdk::HashableKey;
    use sp1_verifier::Groth16Verifier;

    // Load fixtures
    let proof_path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/proof.bin");
    let public_outputs_path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/public_outputs.bin");
    let circuit_elf_path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/circuit.elf");

    let proof_bytes = std::fs::read(proof_path).expect("Failed to read proof.bin");
    let public_values_bytes =
        std::fs::read(public_outputs_path).expect("Failed to read public_outputs.bin");
    let circuit_elf = std::fs::read(circuit_elf_path).expect("Failed to read circuit.elf");

    // Setup prover client and get verification key from the ELF
    let prover_client = ProverClient::from_env();
    let (_pk, vk) = prover_client.setup(&circuit_elf);

    // Verify the Groth16 proof using raw bytes
    Groth16Verifier::verify(
        &proof_bytes,
        &public_values_bytes,
        &vk.bytes32(),
        &sp1_verifier::GROTH16_VK_BYTES,
    )
    .expect("Failed to verify Groth16 proof from fixture");
}

/// Test that writes the compiled circuit ELF to a file.
///
/// This test exports the embedded CIRCUIT_ELF binary to the fixtures directory,
/// which can be useful for debugging, distribution, or external verification.
#[test]
fn test_write_elf_to_file() {
    let output_path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/circuit.elf");

    std::fs::write(output_path, CIRCUIT_ELF).expect("Failed to write ELF to file");

    println!("Successfully wrote circuit ELF to: {}", output_path);

    // Verify the file was written correctly by reading it back
    let written_elf = std::fs::read(output_path).expect("Failed to read back written ELF");

    assert_eq!(
        written_elf.len(),
        CIRCUIT_ELF.len(),
        "Written ELF size should match original"
    );

    assert_eq!(
        written_elf, CIRCUIT_ELF,
        "Written ELF content should match original"
    );
}

/// Test that verifies a TEE quote using dcap_qvl directly.
///
/// This test loads a quote report from fixtures and verifies it using dcap_qvl's
/// verify function (outside of the SP1 circuit). This is useful for testing the
/// quote verification logic independently of ZK proof generation.
#[tokio::test]
async fn test_verify_quote_with_dcap_qvl() {
    let fixture_path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/quote-report.json");
    let json_content = std::fs::read_to_string(fixture_path).expect("Failed to read fixture file");
    let report: QuoteReport = serde_json::from_str(&json_content).expect("Failed to parse JSON");

    // Decode the hex-encoded quote
    let quote = hex::decode(&report.quote).expect("Failed to decode quote hex");

    // Get collateral for the quote
    let collateral = dcap_qvl::collateral::get_collateral(
        "https://pccs.phala.network/sgx/certification/v4/",
        &quote,
    )
    .await
    .expect("Failed to get collateral");

    // Get current timestamp for verification
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Failed to get current time")
        .as_secs();

    // Verify the quote using dcap_qvl
    let verified_report = dcap_qvl::verify::verify(&quote, &collateral, now)
        .expect("Failed to verify quote with dcap_qvl");

    // Validate the verification result
    println!("Verification status: {}", verified_report.status);
    println!("Advisory IDs: {:?}", verified_report.advisory_ids);

    // The status should indicate successful verification
    assert!(
        !verified_report.status.is_empty(),
        "Status should not be empty"
    );

    // Verify that we have a valid report type
    let report_data = if let Some(r) = verified_report.report.as_td10() {
        println!("Verified TD 1.0 report");
        r.report_data
    } else if let Some(r) = verified_report.report.as_td15() {
        println!("Verified TD 1.5 report");
        r.base.report_data
    } else if let Some(r) = verified_report.report.as_sgx() {
        println!("Verified SGX Enclave report");
        r.report_data
    } else {
        panic!("Unknown report type");
    };

    // If the fixture has output data, verify the report_data matches the output hash
    if let Some(output_hex) = &report.output {
        let output = hex::decode(output_hex).expect("Failed to decode output hex");
        let output_hash = sha2::Sha256::digest(&output);

        assert_eq!(
            &output_hash[..],
            &report_data[..32],
            "Output hash should match the first 32 bytes of report_data"
        );
        println!("Report data matches output hash");
    }

    println!("Quote verification successful");
}
