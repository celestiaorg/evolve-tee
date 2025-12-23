use axum::{routing::get, Json, Router};
use dstack_sdk::dstack_client::DstackClient;
use dstack_types::VmConfig;
use dstack_verifier::Attestation;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let app = Router::new()
        .route("/attestation", get(get_attestation))
        .route("/info", get(get_info));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080").await?;
    println!("Listening on http://0.0.0.0:8080");
    axum::serve(listener, app).await?;

    Ok(())
}

async fn get_attestation() -> Json<Value> {
    let client = DstackClient::new(None);

    // Example: attest to application data by hashing it into the 64-byte reportData field
    let app_data = r#"{"app":"evolve-tee","version":"0.1.0"}"#;
    let report_data = sha256(app_data.as_bytes());

    let result = client.get_quote(report_data).await.unwrap();

    // test verification logic
    let quote = hex::decode(&result.quote).unwrap();
    let event_log = result.event_log.as_bytes();
    let vm_config: VmConfig = serde_json::from_str(&result.vm_config).unwrap();

    let attestation = Attestation::new(quote, event_log.to_vec()).unwrap();

    let report_data = attestation.decode_report_data().unwrap();

    attestation
        .clone()
        .verify(
            &report_data,
            Some("https://pccs.phala.network/sgx/certification/v4/"),
        )
        .await
        .unwrap();

    match attestation.decode_app_info(false) {
        Ok(info) => {
            println!("Device ID: {}", hex::encode(info.device_id));
        }
        Err(e) => {
            panic!("Failed to decode app info: {}", e);
        }
    };

    Json(json!({
        "quote": result.quote,
        "event_log": result.event_log,
        "attested_data": app_data,
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
