use tokio;
mod oauth;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Call the OAuth function defined in oauth.rs
    oauth::perform_oauth_flow().await?;

    Ok(())
}
