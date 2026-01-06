use std::sync::Arc;
use std::time::SystemTime;

use alloy::primitives::FixedBytes;
use anyhow::{Context, anyhow};
use celestia_grpc_client::{CelestiaIsmClient, QueryIsmRequest, types::ClientConfig};
use celestia_rpc::HeaderClient;
use dstack_verifier::Attestation;
use ev_prover::{config::Config, prover::chain::ChainContext};
use ev_zkevm_types::programs::block::{BatchExecInput, State};
use light_client::{BATCH_ELF, CIRCUIT_ELF, build_block_input, get_light_block};
use serde::Deserialize;
use sp1_sdk::{ProverClient, SP1Stdin};
use tendermint_rpc::HttpClient as TendermintHttpClient;
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

    // Override default config with remote RPC endpoints
    let mut config = Config::default();
    config.rpc.celestia_rpc = "http://178.199.12.26:26658".to_string();
    config.rpc.evnode_rpc = "http://178.199.12.26:26658".to_string();
    config.rpc.evreth_rpc = "http://178.199.12.26:8545".to_string();
    config.rpc.evreth_ws = "ws://178.199.12.26:8546".to_string();

    let chain_context = ChainContext::from_config(config, Arc::new(ism_client))
        .await
        .unwrap();

    // use remote tendermint rpc
    let tendermint_client = TendermintHttpClient::new("http://178.199.12.26:26657")
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
    let mut block_inputs = Vec::new();
    println!(
        "Building block inputs from {} to {}...",
        trusted_celestia_height + 1,
        celestia_head
    );
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
    println!("Done building block inputs");

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
    let (output, report) = sp1_client.execute(BATCH_ELF, &stdin).run().unwrap();
    println!("Execution cycles: {}", report.total_instruction_count());
    let output: ev_zkevm_types::programs::block::BlockRangeExecOutput =
        bincode::deserialize(&output.as_slice()).unwrap();
    println!("Output: {:?}", output);
    // todo: run the circuit in the TEE, attest to the output and generate a ZKP of the verification with
    // valid state transition output for the ZKISM to consume
}

#[tokio::test]
async fn test_verify_quote() {
    // Read the quote report from fixtures
    let fixture_path = concat!(env!("CARGO_MANIFEST_DIR"), "/fixtures/quote-report.json");
    let json_content = std::fs::read_to_string(fixture_path).expect("Failed to read fixture file");
    let report: QuoteReport = serde_json::from_str(&json_content).expect("Failed to parse JSON");

    // Decode the hex-encoded quote
    let quote = hex::decode(&report.quote).expect("Failed to decode quote hex");
    let event_log = report.event_log.as_bytes();

    // Create attestation from quote and event log
    let attestation =
        Attestation::new(quote.clone(), event_log.to_vec()).expect("Failed to create attestation");

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
    let json_content = std::fs::read_to_string(fixture_path).expect("Failed to read fixture file");
    let report: QuoteReport = serde_json::from_str(&json_content).expect("Failed to parse JSON");

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
        collateral,
        output: Vec::new(),
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

#[derive(Deserialize)]
struct AttestationResponse {
    success: bool,
    quote: Option<String>,
    event_log: Option<String>,
    output: Option<String>,
    #[allow(dead_code)]
    execution_cycles: Option<u64>,
    error: Option<String>,
    step: Option<u32>,
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

    println!("Fetching attestation from {}...", tee_app_url);

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

    println!("Attestation received successfully");
    println!("Output length: {} bytes", output_hex.len() / 2);

    // Decode the hex-encoded values
    let quote = hex::decode(&quote_hex).expect("Failed to decode quote hex");
    let event_log = event_log_str.as_bytes();
    let output = hex::decode(&output_hex).expect("Failed to decode output hex");

    println!("Fetching collateral...");

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

    println!("Setting up prover...");

    let prover_client = ProverClient::from_env();
    let (pk, vk) = prover_client.setup(CIRCUIT_ELF);

    let mut stdin = SP1Stdin::new();
    stdin.write(&inputs);

    println!("Generating proof...");

    let proof = prover_client
        .prove(&pk, &stdin)
        .groth16()
        .run()
        .expect("Failed to generate proof");

    // write proof to file
    std::fs::write("proof.bin", proof.bytes()).expect("Failed to write proof to file");
    // write public outputs to file
    std::fs::write("public_outputs.bin", proof.public_values.to_vec())
        .expect("Failed to write public outputs to file");
    // write elf to file
    std::fs::write("circuit.elf", CIRCUIT_ELF).expect("Failed to write elf to file");

    println!("Proof generated successfully!");
    println!("Public values: {:?}", proof.public_values);

    // Verify the proof
    prover_client
        .verify(&proof, &vk)
        .expect("Failed to verify proof");

    println!("Proof verified successfully!");
}
