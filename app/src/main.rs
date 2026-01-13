use std::sync::Arc;

use alloy::primitives::FixedBytes;
use anyhow::anyhow;
use axum::{routing::get, Json, Router};
use celestia_grpc_client::{types::ClientConfig, CelestiaIsmClient, QueryIsmRequest};
use celestia_rpc::HeaderClient;
use dstack_sdk::dstack_client::DstackClient;
use ev_prover::{config::Config, prover::chain::ChainContext};
use ev_zkevm_types::programs::block::State;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tee_light_client_lib::{fetch_block_inputs_from_middleware, get_light_block, verify_blocks};
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
    // Catch-all error handler
    match get_attestation_inner().await {
        Ok(response) => response,
        Err(e) => {
            eprintln!("FATAL ERROR in get_attestation: {}", e);
            Json(json!({
                "success": false,
                "error": format!("Internal server error: {}", e),
                "step": "unknown"
            }))
        }
    }
}

async fn get_attestation_inner() -> anyhow::Result<Json<Value>> {
    // Step 1: Connect to Celestia ISM
    println!("Step 1: Connecting to Celestia ISM...");
    let client_config = ClientConfig::from_env()
        .map_err(|e| anyhow!("Failed to load Celestia ISM config from environment: {}", e))?;
    let ism_client = CelestiaIsmClient::new(client_config)
        .await
        .map_err(|e| anyhow!("Failed to connect to Celestia ISM: {}", e))?;

    println!("Step 2: Creating chain context...");
    let mut config = Config::default();
    let celestia_rpc_url = std::env::var("CELESTIA_RPC_URL")
        .map_err(|_| anyhow!("CELESTIA_RPC_URL environment variable not set"))?;
    let evnode_rpc_url = std::env::var("EV_NODE_URL")
        .map_err(|_| anyhow!("EV_NODE_URL environment variable not set"))?;
    let evreth_rpc_url = std::env::var("RETH_RPC_URL")
        .map_err(|_| anyhow!("RETH_RPC_URL environment variable not set"))?;
    let evreth_ws_url = std::env::var("RETH_WS_URL")
        .map_err(|_| anyhow!("RETH_WS_URL environment variable not set"))?;
    config.rpc.celestia_rpc = celestia_rpc_url;
    config.rpc.evnode_rpc = evnode_rpc_url;
    config.rpc.evreth_rpc = evreth_rpc_url;
    config.rpc.evreth_ws = evreth_ws_url;
    config.pub_key = "3964a68700cf76e215626e076e76d23bd1f4c3b31184b5822fd7b4df15d5ce9a".to_string();

    let chain_context = ChainContext::from_config(config, Arc::new(ism_client))
        .await
        .map_err(|e| anyhow!("Failed to create chain context: {}", e))?;

    // Step 3: Connect to Tendermint
    println!("Step 3: Connecting to Tendermint...");
    let tendermint_rpc_url = std::env::var("TENDERMINT_RPC_URL")
        .map_err(|_| anyhow!("TENDERMINT_RPC_URL environment variable not set"))?;
    let tendermint_client = TendermintHttpClient::new(tendermint_rpc_url.as_str())
        .map_err(|e| anyhow!("Failed to connect to Tendermint: {}", e))?;

    // Step 4: Query ISM
    println!("Step 4: Querying ISM...");
    let resp = chain_context
        .ism_client()
        .ism(QueryIsmRequest {
            id: chain_context.ism_id().to_string(),
        })
        .await
        .map_err(|e| anyhow!("Failed to query ISM: {}", e))?;

    let ism = resp.ism.ok_or_else(|| anyhow!("ZKISM not found"))?;

    let state: State = bincode::deserialize(&ism.state)
        .map_err(|e| anyhow!("Failed to deserialize state: {}", e))?;

    // Step 5: Get Celestia head
    println!("Step 5: Getting Celestia head...");
    let trusted_celestia_height = state.celestia_height;
    let trusted_height = state.height;
    let trusted_root: FixedBytes<32> = FixedBytes::from_slice(&state.state_root);
    let celestia_head_raw = chain_context
        .celestia_client()
        .header_local_head()
        .await
        .map_err(|e| anyhow!("Failed to get Celestia head: {}", e))?
        .height()
        .value();
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

    let middleware_url = std::env::var("MIDDLEWARE_ENDPOINT")
        .map_err(|_| anyhow!("MIDDLEWARE_ENDPOINT environment variable not set"))?;

    let trusted_root_hex = hex::encode(trusted_root.as_slice());

    let fetch_start = std::time::Instant::now();
    let (block_inputs, _) = fetch_block_inputs_from_middleware(
        &middleware_url,
        trusted_celestia_height + 1,
        celestia_head,
        trusted_height,
        &trusted_root_hex,
    )
    .await
    .map_err(|e| anyhow!("Failed to fetch block inputs from middleware: {}", e))?;
    let fetch_duration = fetch_start.elapsed();
    println!(
        "  Fetch completed in {:.2}s ({} blocks, {:.2}ms per block)",
        fetch_duration.as_secs_f64(),
        num_blocks,
        fetch_duration.as_millis() as f64 / num_blocks as f64
    );

    // Step 7: Get light blocks
    println!("Step 7: Getting light blocks...");
    let trusted_light_block = get_light_block(&tendermint_client, trusted_celestia_height)
        .await
        .map_err(|e| anyhow!("Failed to get trusted light block: {}", e))?;
    let new_light_block = get_light_block(&tendermint_client, celestia_head)
        .await
        .map_err(|e| anyhow!("Failed to get new light block: {}", e))?;
    // Step 8: Native block verification (replaces SP1 execution for TEE)
    println!("Step 8: Running native block verification...");
    let verify_start = std::time::Instant::now();
    let output = verify_blocks(block_inputs, trusted_light_block, new_light_block)
        .await
        .map_err(|e| anyhow!("Block verification failed: {}", e))?;
    let verify_duration = verify_start.elapsed();
    println!(
        "  Verification completed in {:.2}s",
        verify_duration.as_secs_f64()
    );

    // Serialize output (same format as SP1 would commit)
    let output_bytes =
        bincode::serialize(&output).map_err(|e| anyhow!("Failed to serialize output: {}", e))?;

    // Step 9: Get TEE attestation
    println!("Step 9: Getting TEE attestation...");
    let client = DstackClient::new(None);
    let report_data = sha256(&output_bytes);

    let result = client
        .get_quote(report_data)
        .await
        .map_err(|e| anyhow!("Failed to get TEE quote: {}", e))?;

    let response = json!({
        "success": true,
        "quote": result.quote,
        "event_log": result.event_log,
        "output": hex::encode(&output_bytes),
        "timing": {
            "fetch_seconds": fetch_duration.as_secs_f64(),
            "verify_blocks_seconds": verify_duration.as_secs_f64(),
        }
    });

    Ok(Json(response))
}

fn sha256(data: &[u8]) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

async fn get_info() -> Json<Value> {
    let client = DstackClient::new(None);
    match client.info().await {
        Ok(info) => Json(json!(info)),
        Err(e) => Json(json!({
            "success": false,
            "error": format!("Failed to get TEE info: {}", e),
        })),
    }
}
