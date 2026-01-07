use std::sync::Arc;

use alloy::primitives::FixedBytes;
use anyhow::anyhow;
use axum::{routing::get, Json, Router};
use celestia_grpc_client::{types::ClientConfig, CelestiaIsmClient, QueryIsmRequest};
use celestia_rpc::HeaderClient;
use dstack_sdk::dstack_client::DstackClient;
use ev_prover::{config::Config, prover::chain::ChainContext};
use ev_zkevm_types::programs::block::State;
use light_client::{fetch_block_inputs_from_middleware, get_light_block, verify_blocks};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tendermint_rpc::HttpClient as TendermintHttpClient;

const MAX_BLOCKS: u64 = 10000;

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
    config.pub_key = "3964a68700cf76e215626e076e76d23bd1f4c3b31184b5822fd7b4df15d5ce9a".to_string();

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
    let trusted_height = state.height;
    let trusted_root: FixedBytes<32> = FixedBytes::from_slice(&state.state_root);
    let celestia_head_raw = match chain_context.celestia_client().header_local_head().await {
        Ok(h) => h.height().value(),
        Err(e) => {
            return Json(json!({"error": format!("Failed to get Celestia head: {}", e), "step": 5}))
        }
    };
    // Limit to MAX_BLOCKS to prevent OOM
    let celestia_head = celestia_head_raw.min(trusted_celestia_height + MAX_BLOCKS);
    if celestia_head < celestia_head_raw {
        println!(
            "  Limiting from {} blocks to {} (max {})",
            celestia_head_raw - trusted_celestia_height,
            celestia_head - trusted_celestia_height,
            MAX_BLOCKS
        );
    }

    // Step 6: Fetch block inputs from middleware (single network call from TEE)
    let num_blocks = celestia_head - trusted_celestia_height;
    println!(
        "Step 6: Fetching block inputs from middleware for {} to {} ({} blocks)...",
        trusted_celestia_height + 1,
        celestia_head,
        num_blocks
    );

    let middleware_url = match std::env::var("MIDDLEWARE_ENDPOINT") {
        Ok(url) => url,
        Err(_) => {
            return Json(
                json!({"error": "MIDDLEWARE_ENDPOINT environment variable not set", "step": 6}),
            )
        }
    };

    let trusted_root_hex = hex::encode(trusted_root.as_slice());

    let fetch_start = std::time::Instant::now();
    let (block_inputs, middleware_timing) = match fetch_block_inputs_from_middleware(
        &middleware_url,
        trusted_celestia_height + 1,
        celestia_head,
        trusted_height,
        &trusted_root_hex,
    )
    .await
    {
        Ok(result) => result,
        Err(e) => {
            return Json(
                json!({"error": format!("Failed to fetch block inputs from middleware: {}", e), "step": 6}),
            )
        }
    };
    let fetch_duration = fetch_start.elapsed();
    println!(
        "  Fetch completed in {:.2}s ({} blocks, {:.2}ms per block)",
        fetch_duration.as_secs_f64(),
        num_blocks,
        fetch_duration.as_millis() as f64 / num_blocks as f64
    );
    if let Some(ref timing) = middleware_timing {
        println!(
            "  Middleware timing: prefetch={:.2}s, host_executor={:.2}s, executor_inputs={:.2}s",
            timing.prefetch_seconds, timing.host_executor_seconds, timing.executor_inputs_seconds
        );
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
    // Step 8: Native block verification (replaces SP1 execution for TEE)
    println!("Step 8: Running native block verification...");
    let verify_start = std::time::Instant::now();
    let output = match verify_blocks(block_inputs, trusted_light_block, new_light_block).await {
        Ok(o) => o,
        Err(e) => {
            return Json(json!({"error": format!("Block verification failed: {}", e), "step": 8}))
        }
    };
    let verify_duration = verify_start.elapsed();
    println!(
        "  Verification completed in {:.2}s",
        verify_duration.as_secs_f64()
    );

    // Serialize output (same format as SP1 would commit)
    let output_bytes = bincode::serialize(&output).expect("failed to serialize output");

    // Step 9: Get TEE attestation
    println!("Step 9: Getting TEE attestation...");
    let client = DstackClient::new(None);
    let report_data = sha256(&output_bytes);

    let result = match client.get_quote(report_data).await {
        Ok(r) => r,
        Err(e) => {
            return Json(json!({"error": format!("Failed to get TEE quote: {}", e), "step": 9}))
        }
    };

    let mut response = json!({
        "success": true,
        "quote": result.quote,
        "event_log": result.event_log,
        "output": hex::encode(&output_bytes),
        "timing": {
            "fetch_seconds": fetch_duration.as_secs_f64(),
            "verify_blocks_seconds": verify_duration.as_secs_f64(),
        }
    });

    // Add middleware timing if available
    if let Some(timing) = middleware_timing {
        response["timing"]["middleware"] = json!({
            "prefetch_seconds": timing.prefetch_seconds,
            "host_executor_seconds": timing.host_executor_seconds,
            "executor_inputs_seconds": timing.executor_inputs_seconds,
            "total_seconds": timing.total_seconds,
        });
    }

    Json(response)
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
