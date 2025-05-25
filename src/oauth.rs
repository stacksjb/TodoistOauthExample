use oauth2::{AuthUrl, ClientId, ClientSecret, TokenUrl, RedirectUrl, AuthCode};
use oauth2::basic::{BasicClient};
use tungstenite::protocol::Message;
use tokio::net::TcpListener;
use std::net::SocketAddr;
use futures_util::stream::StreamExt;
use futures_util::sink::SinkExt;

pub async fn perform_oauth_flow() -> Result<(), Box<dyn std::error::Error>> {
    // Setup OAuth client
    let client_id = "your_todoist_client_id";  // replace with your Todoist client ID
    let client_secret = "your_todoist_client_secret";  // replace with your Todoist client secret
    let auth_url = AuthUrl::new("https://todoist.com/oauth/authorize".to_string())?;
    let token_url = TokenUrl::new("https://todoist.com/oauth/access_token".to_string())?;
    let redirect_url = RedirectUrl::new("http://localhost:8080/callback".to_string())?;

    let client = BasicClient::new(
        ClientId::new(client_id.to_string()),
        Some(ClientSecret::new(client_secret.to_string())),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(redirect_url);

    // Generate the OAuth authorization URL
    let (auth_url, _) = client.authorize_url(|| "state").url();

    // Print the URL and instruct the user to visit it
    println!("Please open the following URL in your browser to authenticate:\n{}", auth_url);
    println!("If the URL is not clickable, copy and paste it into your browser.");

    // Set up a listener to receive the OAuth response
    let addr: SocketAddr = "127.0.0.1:8080".parse()?;
    let listener = TcpListener::bind(&addr).await?;
    println!("Waiting for OAuth response on http://localhost:8080/callback...");

    // Accept the incoming connection
    let (mut socket, _) = listener.accept().await?;
    println!("Received OAuth callback.");

    // Wait for the OAuth authorization code in the WebSocket response
    let mut buffer = Vec::new();
    while let Some(message) = socket.next().await {
        match message {
            Ok(Message::Text(text)) => {
                buffer.push(text);
                break;
            }
            _ => {}
        }
    }

    // Extract the authorization code from the request
    let authorization_code = buffer.pop().unwrap();
    println!("Authorization code received: {}", authorization_code);

    // Exchange the authorization code for an access token
    let token = client.exchange_code(AuthCode::new(authorization_code))
        .request_async(oauth2::reqwest::async_http_client)
        .await?;

    // Display the OAuth token
    println!("Authenticated successfully! Your OAuth token is: {}", token.access_token().secret());

    // Send a response to the client (browser) confirming success
    socket.send(Message::Text("Authenticated successfully, you may now close this window.".to_string()))
        .await?;

    Ok(())
}
