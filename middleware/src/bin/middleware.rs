use anyhow::Result;
use axum::Router;

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .unwrap();

    // Load environment variables
    dotenvy::dotenv().ok();

    println!("Starting middleware server...");

    let app = Router::new()
        .merge(middleware::create_router())
        .route("/health", axum::routing::get(middleware::health_check));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:9091").await?;
    println!("Middleware listening on http://0.0.0.0:9091");

    axum::serve(listener, app).await?;

    Ok(())
}
