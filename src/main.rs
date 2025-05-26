use rand::distr::Alphanumeric;
use rand::Rng;
use reqwest::Client;
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};

// Struct to hold the parsed TokenRequest parameters

// Prompt the user to authenticate with Todoist and get an OAuth token

// Stored variables for  client_id and redirect_uri
const CLIENT_ID: &str = "a32c7ad31aba4421a23845e4ee7c12e0"; // Need to embed into application/config
const CLIENT_SECRET: &str = "9da932be947d479f8932858a93b8d3bf"; // Need to embed into application/configa
const REDIRECT_URI: &str = "http://localhost:8080/callback"; // URI that will handle the OAuth callback - Needs to match the one reigstered with Todoist - This is the URI that the user will be redirected to after authentication
const AUTH_URL: &str = "https://todoist.com/oauth/authorize"; // The URL to prompt the user to go for authentication
const SCOPE: &str = "data:read_write,data:delete,project:delete"; // The scope of the access TokenRequest

// Function to generate the OAuth URL with the required parameters
fn generate_oauth_url(csrf_secret: &str) -> String {
    format!(
        "{}?client_id={}&scope={}&state={}&response_type=code&redirect_uri={}",
        AUTH_URL, CLIENT_ID, SCOPE, csrf_secret, REDIRECT_URI
    )
}

// Function to generate the secret (32 random alphanum chars) for CSRF protection
fn generate_csrf_secret() -> String {
    let mut rng = rand::rng();
    let secret: String = (0..32).map(|_| rng.sample(Alphanumeric) as char).collect();
    secret.trim().to_string()
}

fn parse_query_params(token_request: &str, csrf_secret: &str) -> Result<String, String> {
    if let Some(query_start) = token_request.find('?') {
        let query = &token_request[query_start + 1..]; // Skip the "?"

        // Use `url::Url` to parse the query string correctly
        let url = match url::Url::parse(&format!("http://localhost?{}", query)) {
            Ok(u) => u,
            Err(_) => return Err("Failed to parse URL".to_string()), // Return error if URL parsing fails
        };

        let params = url
            .query_pairs()
            .into_owned()
            .collect::<Vec<(String, String)>>();

        let mut code = None;
        let mut state = None;

        // Extract `code` and `state` from the query parameters
        for (key, value) in params {
            match key.as_str() {
                "code" => code = Some(value),
                "state" => state = Some(value),
                _ => {}
            }
        }

        // Check if both `code` and `state` are present
        if let (Some(code), Some(state)) = (code, state) {
            // Remove any leading/trailing spaces from `state` and `csrf_secret`
            // Grab the first 32 characters of `state` to match the CSRF secret
            let state = state.chars().take(32).collect::<String>();
            let state = state.trim();
            let csrf_secret = csrf_secret.trim();
            // Compare the incoming `state` with the expected `csrf_secret`
            if state == csrf_secret {
                // Return success if the state matches
                return Ok(code);
            } else {
                // Log both values for debugging purposes
                println!("Expected CSRF secret: {}", csrf_secret);
                println!("Received state: {}", state);

                // Return error if the state does not match
                return Err(format!(
                    "State mismatch: Expected {}, got {}",
                    csrf_secret, state
                ));
            }
        } else {
            // Return error if either `code` or `state` is missing
            return Err("Missing or invalid query parameters".to_string());
        }
    }

    Err("No query string found".to_string()) // Return error if no query string is found
}

fn handle_client(mut stream: TcpStream, csrf_secret: &str) -> Result<String, String> {
    let mut buffer = [0; 2048]; // Increased buffer size to handle larger TokenRequests
    match stream.read(&mut buffer) {
        Ok(bytes_read) => {
            // Read the incoming TokenRequest and extract the first line
            let token_request = String::from_utf8_lossy(&buffer[..bytes_read]).to_string();

            // Check if the TokenRequest starts with "GET"
            if token_request.starts_with("GET") {
                // Parse query parameters from the URL and check for state match
                match parse_query_params(&token_request, csrf_secret) {
                    Ok(code) => {
                        // Success, send back the success message
                        let response_message = "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nAuthentication Successful! You may now close this window.";
                        stream.write_all(response_message.as_bytes()).unwrap();
                        // Return the OAuth code instead of printing
                        Ok(code) // Return the code to the caller
                    }
                    Err(error_message) => {
                        // Error with state mismatch or missing parameters
                        let error_response =
                            format!("HTTP/1.1 400 Bad Request\r\n\r\n{}", error_message);
                        stream.write_all(error_response.as_bytes()).unwrap();
                        Err(error_message) // Return the error to the caller
                    }
                }
            } else {
                // Unsupported HTTP method
                let error_message =
                    "HTTP/1.1 405 Method Not Allowed\r\n\r\nOnly GET requests are supported";
                stream.write_all(error_message.as_bytes()).unwrap();
                Err("Unsupported HTTP method".to_string()) // Return error to the caller
            }
        }
        Err(_) => {
            let error_message = "HTTP/1.1 500 Internal Server Error\r\n\r\nError reading request";
            stream.write_all(error_message.as_bytes()).unwrap();
            Err("Error reading request".to_string()) // Return error to the caller
        }
    }
}

fn token_listen(port: u16, csrf_secret: &str) -> Result<String, String> {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .map_err(|_| "Failed to bind to the port")?;

    println!("Listening on port {}", port);

    // Accept one incoming connection
    if let Some(stream) = listener.incoming().next() {
        match stream {
            Ok(stream) => {
                // Handle client connection and pass csrf_secret to it, getting the result (OAuth code or error)
                match handle_client(stream, csrf_secret) {
                    Ok(code) => {
                        // Return the OAuth code received from handle_client
                        return Ok(code); // Return the code to the caller
                    }
                    Err(error_message) => {
                        // Return the error message if handle_client fails
                        return Err(error_message); // Propagate the error
                    }
                }
            }
            Err(_) => {
                eprintln!("Connection failed");
                return Err("Connection failed".to_string()); // Error if connection fails
            }
        }
    }

    Err("Server stopped".to_string()) // If the server is stopped
}

#[derive(Deserialize)]
struct AccessTokenResponse {
    access_token: String,
    token_type: String,
}

// Function to get the access token using the code
async fn get_access_token(code: &str) -> Result<String, String> {
    // Create a reqwest client
    let client = Client::new();

    // Prepare the URL and parameters
    let url = "https://todoist.com/oauth/access_token";
    let params = [
        ("client_id", CLIENT_ID),
        ("client_secret", CLIENT_SECRET),
        ("code", code),
    ];

    // Send the POST request
    let response = client
        .post(url)
        .form(&params)
        .send()
        .await
        .map_err(|_| "Failed to send the request".to_string())?;

    // Check if the response is OK
    if !response.status().is_success() {
        return Err("Failed to get access token, server returned an error".to_string());
    }

    // Parse the JSON response to extract the access_token and token_type
    let access_token_response: AccessTokenResponse = response
        .json()
        .await
        .map_err(|_| "Failed to parse the response body".to_string())?;

    // Validate that the token_type is "Bearer"
    if access_token_response.token_type != "Bearer" {
        return Err(format!(
            "Invalid token type: Expected 'Bearer', got '{}'",
            access_token_response.token_type
        ));
    }

    // Validate the presence of the access token
    if access_token_response.access_token.is_empty() {
        return Err("Access token is missing in the response".to_string());
    }

    // Return the access token
    Ok(access_token_response.access_token)
}

#[tokio::main]
async fn main() {
    // Generate a CSRF secret for the OAuth flow
    let csrf_secret = generate_csrf_secret();

    // Generate the OAuth URL and print it for the user to visit
    let oauth_url = generate_oauth_url(&csrf_secret);

    println!("Please visit the following URL to authenticate:");
    println!("{}", oauth_url);

    // Start the local server to listen for the OAuth callback
    println!("Listening for OAuth callback on http://localhost:8080/callback");
    println!("Listening for CSRF secret: {}", csrf_secret);
    // Start the token listener on port 8080 and handle the result
    match token_listen(8080, &csrf_secret) {
        Ok(code) => {
            println!("Received OAuth code: {}", code); // This will print the OAuth code returned by token_listen

            // Now get the access token using the received code
            match get_access_token(&code).await {
                Ok(access_token) => {
                    println!("Received access token: {}", access_token);
                }
                Err(error_message) => {
                    eprintln!("Error getting access token: {}", error_message);
                }
            }
        }
        Err(error_message) => {
            eprintln!("Error: {}", error_message); // Handle the error if something goes wrong
        }
    }
}
