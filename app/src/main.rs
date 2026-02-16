use anyhow::anyhow;
use axum::{
    routing::{get, post},
    Json, Router,
};
use dstack_sdk::dstack_client::DstackClient;
use ev_zkevm_types::programs::block::{BlockExecInput, BlockVerifier};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[derive(Deserialize, Serialize)]
struct AttestationRequest {
    block_inputs: Vec<String>,
    trusted_light_block_raw: String,
    new_light_block_raw: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Initialize crypto provider
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|_| anyhow!("Failed to install default crypto provider"))?;

    dotenvy::dotenv().ok();

    let app = Router::new()
        .route("/attestation", post(get_attestation))
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

// Health check
async fn health_check() -> Json<Value> {
    Json(json!({
        "status": "ok",
    }))
}

async fn get_attestation(Json(request): Json<AttestationRequest>) -> Json<Value> {
    // Catch-all error handler
    match get_attestation_inner(request).await {
        Ok(response) => response,
        Err(e) => {
            eprintln!("FATAL ERROR in get_attestation: {}", e);
            Json(json!({
                "success": false,
                "error": format!("Internal server error: {}", e),
            }))
        }
    }
}

async fn get_attestation_inner(request: AttestationRequest) -> anyhow::Result<Json<Value>> {
    // Step 1: Deserialize block inputs from hex strings
    println!("Step 1: Deserializing block inputs...");
    let deserialize_start = std::time::Instant::now();
    let mut block_inputs: Vec<BlockExecInput> = Vec::new();
    for hex_str in &request.block_inputs {
        let bytes =
            hex::decode(hex_str).map_err(|e| anyhow!("Failed to decode block input hex: {}", e))?;
        let input: BlockExecInput = bincode::deserialize(&bytes)
            .map_err(|e| anyhow!("Failed to deserialize block input: {}", e))?;
        block_inputs.push(input);
    }
    let deserialize_duration = deserialize_start.elapsed();
    println!(
        "  Deserialized {} block inputs in {:.2}s",
        block_inputs.len(),
        deserialize_duration.as_secs_f64()
    );

    if block_inputs.is_empty() {
        return Err(anyhow!("No block inputs provided"));
    }

    // Step 2: Deserialize light blocks from hex strings
    println!("Step 2: Deserializing light blocks...");
    let trusted_light_block_bytes = hex::decode(&request.trusted_light_block_raw)
        .map_err(|e| anyhow!("Failed to decode trusted light block hex: {}", e))?;
    let trusted_light_block = serde_cbor::from_slice(&trusted_light_block_bytes)
        .map_err(|e| anyhow!("Failed to deserialize trusted light block: {}", e))?;

    let new_light_block_bytes = hex::decode(&request.new_light_block_raw)
        .map_err(|e| anyhow!("Failed to decode new light block hex: {}", e))?;
    let new_light_block = serde_cbor::from_slice(&new_light_block_bytes)
        .map_err(|e| anyhow!("Failed to deserialize new light block: {}", e))?;

    // Step 3: Native block verification (replaces SP1 execution for TEE)
    println!("Step 3: Running native block verification...");
    let verify_start = std::time::Instant::now();
    let verifier = BlockVerifier {};
    let output = verifier
        .verify_range(block_inputs, trusted_light_block, new_light_block)
        .map_err(|e| anyhow!("Block verification failed: {}", e))?;
    let verify_duration = verify_start.elapsed();
    println!(
        "  Verification completed in {:.2}s",
        verify_duration.as_secs_f64()
    );

    // Serialize output (same format as SP1 would commit)
    let output_bytes =
        bincode::serialize(&output).map_err(|e| anyhow!("Failed to serialize output: {}", e))?;

    // Step 4: Get TEE attestation
    println!("Step 4: Getting TEE attestation...");
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
            "deserialize_seconds": deserialize_duration.as_secs_f64(),
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
