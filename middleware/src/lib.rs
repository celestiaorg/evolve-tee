use std::sync::Arc;

use alloy::primitives::FixedBytes;
use anyhow::{anyhow, Result};
use axum::{extract::Query, routing::get, Json, Router};
use celestia_grpc_client::{types::ClientConfig, CelestiaIsmClient};
use ev_prover::{config::Config, prover::chain::ChainContext};
use ev_zkevm_types::programs::block::BlockExecInput;
use light_client::{build_block_input_from_prefetched, prefetch_celestia_data_batch};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

#[derive(Debug, Deserialize)]
pub struct QueryBlockInputsParams {
    pub from_height: u64,
    pub to_height: u64,
    pub trusted_height: u64,
    pub trusted_root: String,
}

#[derive(Debug, Serialize)]
pub struct QueryBlockInputsResponse {
    pub success: bool,
    pub block_inputs: Option<Vec<String>>,
    pub error: Option<String>,
    pub timing: Option<TimingInfo>,
}

#[derive(Debug, Serialize)]
pub struct TimingInfo {
    pub total_time_seconds: f64,
}

pub fn create_router() -> Router {
    Router::new().route("/query_block_inputs", get(query_block_inputs))
}

async fn query_block_inputs(
    Query(params): Query<QueryBlockInputsParams>,
) -> Json<QueryBlockInputsResponse> {
    match fetch_block_inputs(params).await {
        Ok((block_inputs, timing)) => {
            let serialized_inputs: Vec<String> = block_inputs
                .into_iter()
                .map(|input| {
                    let bytes = bincode::serialize(&input).expect("failed to serialize input");
                    hex::encode(bytes)
                })
                .collect();

            Json(QueryBlockInputsResponse {
                success: true,
                block_inputs: Some(serialized_inputs),
                error: None,
                timing: Some(timing),
            })
        }
        Err(e) => Json(QueryBlockInputsResponse {
            success: false,
            block_inputs: None,
            error: Some(e.to_string()),
            timing: None,
        }),
    }
}

async fn fetch_block_inputs(params: QueryBlockInputsParams) -> Result<(Vec<BlockExecInput>, TimingInfo)> {
    let total_start = std::time::Instant::now();

    // Parse trusted root from hex string
    let trusted_root_bytes = hex::decode(&params.trusted_root)
        .map_err(|e| anyhow!("Invalid trusted_root hex: {}", e))?;
    if trusted_root_bytes.len() != 32 {
        return Err(anyhow!(
            "trusted_root must be 32 bytes, got {}",
            trusted_root_bytes.len()
        ));
    }
    let mut trusted_root = FixedBytes::<32>::default();
    trusted_root.copy_from_slice(&trusted_root_bytes);
    let mut trusted_height = params.trusted_height;

    // Connect to Celestia ISM
    let ism_client = CelestiaIsmClient::new(ClientConfig::from_env()?)
        .await
        .map_err(|e| anyhow!("Failed to connect to Celestia ISM: {}", e))?;

    // Create chain context
    let mut config = Config::default();
    config.rpc.celestia_rpc =
        std::env::var("CELESTIA_RPC_URL").map_err(|_| anyhow!("CELESTIA_RPC_URL not set"))?;
    config.rpc.evnode_rpc =
        std::env::var("EV_NODE_URL").map_err(|_| anyhow!("EV_NODE_URL not set"))?;
    config.rpc.evreth_rpc =
        std::env::var("RETH_RPC_URL").map_err(|_| anyhow!("RETH_RPC_URL not set"))?;
    config.rpc.evreth_ws =
        std::env::var("RETH_WS_URL").map_err(|_| anyhow!("RETH_WS_URL not set"))?;
    config.pub_key = std::env::var("PUBKEY").unwrap_or_else(|_| {
        "3964a68700cf76e215626e076e76d23bd1f4c3b31184b5822fd7b4df15d5ce9a".to_string()
    });

    let chain_context = ChainContext::from_config(config, Arc::new(ism_client))
        .await
        .map_err(|e| anyhow!("Failed to create chain context: {}", e))?;

    // Batch prefetch Celestia data and process blocks
    let prefetched =
        prefetch_celestia_data_batch(chain_context.clone(), params.from_height, params.to_height)
            .await?;

    // Process sequentially to handle trusted state updates (includes executor input generation)
    let mut block_inputs = Vec::new();
    for prefetched_data in prefetched {
        let (input, _) = build_block_input_from_prefetched(
            chain_context.clone(),
            prefetched_data,
            &mut trusted_height,
            &mut trusted_root,
        )
        .await?;
        block_inputs.push(input);
    }

    let total_duration = total_start.elapsed();

    let timing = TimingInfo {
        total_time_seconds: total_duration.as_secs_f64(),
    };

    println!(
        "Timing report: total={:.2}s (includes Celestia fetch + RPC state fetch + execution)",
        timing.total_time_seconds
    );

    Ok((block_inputs, timing))
}

pub async fn health_check() -> Json<Value> {
    let celestia_rpc = std::env::var("CELESTIA_RPC_URL").unwrap_or_default();
    let evnode_rpc = std::env::var("EV_NODE_URL").unwrap_or_default();

    Json(json!({
        "status": "ok",
        "celestia_rpc_url": celestia_rpc,
        "evnode_rpc_url": evnode_rpc,
    }))
}
