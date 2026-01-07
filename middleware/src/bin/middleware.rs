use anyhow::Result;
use axum::Router;

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables
    dotenvy::dotenv().ok();

    println!("Starting middleware server...");

    let app = Router::new()
        .merge(middleware::create_router())
        .route("/health", axum::routing::get(middleware::health_check));

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await?;
    println!("Middleware listening on http://0.0.0.0:8081");

    axum::serve(listener, app).await?;

    Ok(())
}
