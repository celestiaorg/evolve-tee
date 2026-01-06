use std::sync::Arc;

use alloy::primitives::FixedBytes;
use anyhow::anyhow;
use axum::{routing::get, Json, Router};
use celestia_grpc_client::{types::ClientConfig, CelestiaIsmClient, QueryIsmRequest};
use celestia_rpc::HeaderClient;
use dstack_sdk::dstack_client::DstackClient;
use dstack_verifier::Attestation;
use ev_prover::{config::Config, prover::chain::ChainContext};
use ev_zkevm_types::programs::block::{BatchExecInput, State};
use light_client::{build_block_input, get_light_block, BATCH_ELF};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use sp1_sdk::{ProverClient, SP1Stdin};
use tendermint_rpc::HttpClient as TendermintHttpClient;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize crypto provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow!("Failed to install default crypto provider"))?;

    dotenvy::dotenv().ok();

    let app = Router::new()
        .route("/attestation", get(get_attestation))
        .route("/info", get(get_info))
        .route("/quote", get(get_simple_quote))
        .route("/health", get(health_check));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    println!("Listening on http://0.0.0.0:8080");
    axum::serve(listener, app).await?;

    Ok(())
}

// Simple TEE quote - no external dependencies
async fn get_simple_quote() -> Json<Value> {
    let client = DstackClient::new(None);
    // Report data must be exactly 64 bytes for SGX quotes
    let report_data = vec![0u8; 64];
    match client.get_quote(report_data).await {
        Ok(result) => Json(json!({
            "success": true,
            "quote": result.quote,
            "event_log": result.event_log,
        })),
        Err(e) => Json(json!({
            "success": false,
            "error": e.to_string(),
        })),
    }
}

// Health check with connectivity test
async fn health_check() -> Json<Value> {
    let tendermint_url = std::env::var("TENDERMINT_RPC_URL").unwrap_or_default();
    let celestia_grpc = std::env::var("CELESTIA_GRPC_ENDPOINT").unwrap_or_default();

    Json(json!({
        "status": "ok",
        "tendermint_rpc_url": tendermint_url,
        "celestia_grpc_endpoint": celestia_grpc,
    }))
}

async fn get_attestation() -> Json<Value> {
    // Step 1: Connect to Celestia ISM
    println!("Step 1: Connecting to Celestia ISM...");
    let ism_client = match CelestiaIsmClient::new(ClientConfig::from_env().unwrap()).await {
        Ok(c) => c,
        Err(e) => {
            return Json(
                json!({"error": format!("Failed to connect to Celestia ISM: {}", e), "step": 1}),
            )
        }
    };

    println!("Step 2: Creating chain context...");
    let mut config = Config::default();
    let celestia_rpc_url = std::env::var("CELESTIA_RPC_URL").unwrap();
    let evnode_rpc_url = std::env::var("EV_NODE_URL").unwrap();
    let evreth_rpc_url = std::env::var("RETH_RPC_URL").unwrap();
    let evreth_ws_url = std::env::var("RETH_WS_URL").unwrap();
    config.rpc.celestia_rpc = celestia_rpc_url;
    config.rpc.evnode_rpc = evnode_rpc_url;
    config.rpc.evreth_rpc = evreth_rpc_url;
    config.rpc.evreth_ws = evreth_ws_url;
    let chain_context = match ChainContext::from_config(config, Arc::new(ism_client)).await {
        Ok(c) => c,
        Err(e) => {
            return Json(
                json!({"error": format!("Failed to create chain context: {}", e), "step": 2}),
            )
        }
    };

    // Step 3: Connect to Tendermint
    println!("Step 3: Connecting to Tendermint...");
    let tendermint_rpc_url = std::env::var("TENDERMINT_RPC_URL").unwrap();
    let tendermint_client = match TendermintHttpClient::new(tendermint_rpc_url.as_str()) {
        Ok(c) => c,
        Err(e) => {
            return Json(
                json!({"error": format!("Failed to connect to Tendermint: {}", e), "step": 3}),
            )
        }
    };

    // Step 4: Query ISM
    println!("Step 4: Querying ISM...");
    let resp = match chain_context
        .ism_client()
        .ism(QueryIsmRequest {
            id: chain_context.ism_id().to_string(),
        })
        .await
    {
        Ok(r) => r,
        Err(e) => return Json(json!({"error": format!("Failed to query ISM: {}", e), "step": 4})),
    };

    let ism = match resp.ism {
        Some(i) => i,
        None => return Json(json!({"error": "ZKISM not found", "step": 4})),
    };

    let state: State = match bincode::deserialize(&ism.state) {
        Ok(s) => s,
        Err(e) => {
            return Json(json!({"error": format!("Failed to deserialize state: {}", e), "step": 4}))
        }
    };

    // Step 5: Get Celestia head
    println!("Step 5: Getting Celestia head...");
    let trusted_celestia_height = state.celestia_height;
    let mut trusted_height = state.height;
    let mut trusted_root = FixedBytes::from_slice(&state.state_root);
    let celestia_head = match chain_context.celestia_client().header_local_head().await {
        Ok(h) => h.height().value(),
        Err(e) => {
            return Json(json!({"error": format!("Failed to get Celestia head: {}", e), "step": 5}))
        }
    };

    // Step 6: Build block inputs
    println!(
        "Step 6: Building block inputs from {} to {}...",
        trusted_celestia_height + 1,
        celestia_head
    );
    let mut block_inputs = Vec::new();
    for block_number in trusted_celestia_height + 1..=celestia_head {
        match build_block_input(
            chain_context.clone(),
            block_number,
            &mut trusted_height,
            &mut trusted_root,
        )
        .await
        {
            Ok(input) => block_inputs.push(input),
            Err(e) => {
                return Json(
                    json!({"error": format!("Failed to build block input {}: {}", block_number, e), "step": 6}),
                )
            }
        }
    }

    // Step 7: Get light blocks
    println!("Step 7: Getting light blocks...");
    let trusted_light_block = match get_light_block(&tendermint_client, trusted_celestia_height)
        .await
    {
        Ok(b) => b,
        Err(e) => {
            return Json(
                json!({"error": format!("Failed to get trusted light block: {}", e), "step": 7}),
            )
        }
    };
    let new_light_block = match get_light_block(&tendermint_client, celestia_head).await {
        Ok(b) => b,
        Err(e) => {
            return Json(
                json!({"error": format!("Failed to get new light block: {}", e), "step": 7}),
            )
        }
    };
    let trusted_light_block_raw = serde_cbor::to_vec(&trusted_light_block).unwrap();
    let new_light_block_raw = serde_cbor::to_vec(&new_light_block).unwrap();

    let inputs = BatchExecInput {
        blocks: block_inputs,
        trusted_light_block_raw,
        new_light_block_raw,
    };

    // Step 8: SP1 execution
    println!("Step 8: Running SP1 execution...");
    let sp1_client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write(&inputs);
    let (output, report) = match sp1_client.execute(BATCH_ELF, &stdin).run() {
        Ok(r) => r,
        Err(e) => return Json(json!({"error": format!("SP1 execution failed: {}", e), "step": 8})),
    };
    println!("Execution cycles: {}", report.total_instruction_count());

    // Step 9: Get TEE attestation
    println!("Step 9: Getting TEE attestation...");
    let client = DstackClient::new(None);
    let output_bytes = output.as_slice();
    let report_data = sha256(output_bytes);

    let result = match client.get_quote(report_data).await {
        Ok(r) => r,
        Err(e) => {
            return Json(json!({"error": format!("Failed to get TEE quote: {}", e), "step": 9}))
        }
    };

    Json(json!({
        "success": true,
        "quote": result.quote,
        "event_log": result.event_log,
        "output": hex::encode(output_bytes),
        "execution_cycles": report.total_instruction_count(),
    }))
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

async fn get_info() -> Json<Value> {
    let client = DstackClient::new(None);
    let info = client.info().await.unwrap();
    Json(json!(info))
}
