# Google OAuth Security Plugin

This document describes the Google OAuth 2.0 security plugin implementation for the Classic Diagnostic Adapter.

## Overview

The Google OAuth Security Plugin provides authentication and authorization using Google's OAuth 2.0 and OpenID Connect services. It integrates seamlessly with the CDA security plugin architecture while leveraging Google's robust identity platform.

This implementation uses the **desktop/installed application flow** where users authenticate in their browser and manually copy the authorization code back to the application.

## Features

- **OAuth 2.0 Desktop Flow**: Implements the desktop/installed application flow without redirect URIs
- **OpenID Connect**: Validates ID tokens from Google
- **JWT Token Authentication**: Uses Google ID tokens as Bearer tokens
- **Environment-Based Configuration**: Simple configuration via environment variables
- **SOVD Compliant**: Follows SOVD security specifications

## Configuration

The plugin is configured using environment variables:

### Required Environment Variables

- `GOOGLE_CLIENT_ID`: Your OAuth 2.0 client ID from Google Cloud Console
- `GOOGLE_CLIENT_SECRET`: Your OAuth 2.0 client secret from Google Cloud Console

### Setting up Google Cloud OAuth 2.0

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Navigate to **APIs & Services** > **Credentials**
4. Click **Create Credentials** > **OAuth client ID**
5. Select **Desktop app** as the application type
6. Give it a name (e.g., "CDA Desktop Client")
7. Copy the **Client ID** and **Client Secret**

**Note**: Desktop applications do not require redirect URIs. The authorization code will be displayed in the browser for manual copying.

### Example Configuration

```bash
export GOOGLE_CLIENT_ID="123456789-abcdefghijklmnop.apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="GOCSPX-your_client_secret_here"
```

## Usage

### 1. Initialize the Plugin

In your application startup code:

```rust
use cda_plugin_security::GoogleOAuthSecurityPlugin;

fn main() -> Result<(), String> {
    // Initialize the OAuth configuration from environment variables
    GoogleOAuthSecurityPlugin::init()?;
    
    // ... rest of your application setup
    Ok(())
}
```

### 2. Launch Webserver with Google OAuth Plugin

When launching the webserver, specify `GoogleOAuthSecurityPlugin` as the security plugin type:

```rust
use cda_plugin_security::GoogleOAuthSecurityPlugin;
use cda_sovd::{launch_webserver, WebServerConfig};

#[tokio::main]
async fn main() -> Result<(), String> {
    // Initialize the plugin
    GoogleOAuthSecurityPlugin::init()?;
    
    let config = WebServerConfig {
        host: "0.0.0.0".to_string(),
        port: 8080,
    };
    
    let shutdown_signal = /* ... */;
    
    // Launch webserver with Google OAuth security
    launch_webserver(config, shutdown_signal).await?;
    
    Ok(())
}
```

## Desktop OAuth Flow

### Step 1: Initiate Authorization

The client sends a POST request to initiate the OAuth flow:

**Request:**
```http
POST /vehicle/v15/authorize HTTP/1.1
Content-Type: application/json

{
  "state": "random-csrf-token",
  "scopes": ["openid", "email", "profile"]
}
```

**Response:**
```json
{
  "authorization_url": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...&redirect_uri=urn:ietf:wg:oauth:2.0:oob&response_type=code&scope=openid%20email%20profile&state=random-csrf-token",
  "state": "random-csrf-token"
}
```

### Step 2: User Authentication

The client opens the `authorization_url` in a browser. The user:
1. Logs into their Google account (if not already logged in)
2. Reviews the requested permissions
3. Grants or denies access
4. **Copies the authorization code displayed in the browser**

Google displays the authorization code in the browser using the `urn:ietf:wg:oauth:2.0:oob` redirect URI, which is specifically designed for desktop and installed applications.

### Step 3: Exchange Code for Token

The user pastes the authorization code into the client application, which then exchanges it for an access token:

**Request:**
```http
POST /vehicle/v15/oauth/callback HTTP/1.1
Content-Type: application/json

{
  "code": "4/0AY0e-...",
  "state": "random-csrf-token"
}
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6IjE2...",
  "token_type": "Bearer",
  "expires_in": 3599
}
```

### Step 4: Accessing Protected Resources

Use the access token (ID token) as a Bearer token in the Authorization header:

**Request:**
```http
GET /vehicle/v15/components HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6IjE2...
```

The security plugin will:
1. Extract the Bearer token
2. Verify the ID token signature using Google's JWKS public keys
3. Validate the token claims (issuer, audience, expiration)
4. Create a security context with user claims
5. Allow or deny access based on validation

## Security Considerations

### Desktop Application Security

Since this implementation uses the desktop/installed application flow:

1. **Authorization Code Handling**:
   - Authorization codes are single-use only
   - They should be exchanged for tokens immediately after receipt
   - Never log or store authorization codes

2. **Client Secret Protection**:
   - While desktop apps cannot fully protect secrets, use environment variables
   - Consider using PKCE (Proof Key for Code Exchange) for additional security
   - Rotate secrets regularly if compromised

### Production Deployment

✅ **Token Verification**: The implementation now includes production-ready JWT verification:
- Fetches and caches Google's public keys from the JWKS endpoint
- Verifies token signatures using RSA public keys
- Validates issuer, audience, and expiration
- Caches JWKS keys for 1 hour (as recommended by Google)

⚠️ **Additional Security Considerations** for production deployments:

1. **Secure Secret Management**:
   - Never commit secrets to version control
   - Use secret management services (AWS Secrets Manager, HashiCorp Vault, etc.)
   - Rotate secrets regularly

2. **State Validation**:
   - Validate the state parameter to prevent CSRF attacks
   - Store state values securely until validation completes

3. **Token Storage** (Client-Side):
   - Store tokens securely on the client side
   - Use OS-level secure storage mechanisms when available
   - Implement token refresh mechanisms

4. **HTTPS/TLS**:
   - Always use HTTPS in production to protect tokens in transit
   - Use valid TLS certificates from trusted CAs

5. **Rate Limiting**:
   - Implement rate limiting on OAuth endpoints
   - Protect against brute force and DoS attacks

## API Reference

### Types

#### `GoogleOAuthConfig`
Configuration for Google OAuth loaded from environment variables.

Fields:
- `client_id`: OAuth client ID from Google Cloud Console
- `client_secret`: OAuth client secret from Google Cloud Console

#### `GoogleClaims`
JWT claims extracted from Google ID tokens.

Fields:
- `sub`: User identifier
- `email`: User's email address
- `email_verified`: Whether email is verified
- `iss`: Token issuer
- `aud`: Token audience (client ID)
- `iat`: Issued at timestamp
- `exp`: Expiration timestamp

#### `OAuthAuthorizationRequest`
Request payload for initiating OAuth flow.

Fields:
- `state`: Optional CSRF token
- `scopes`: Optional list of scopes to request

#### `OAuthAuthorizationResponse`
Response containing the authorization URL.

Fields:
- `authorization_url`: URL to redirect user to
- `state`: State parameter for verification

#### `OAuthCallbackRequest`
Request payload for the OAuth callback.

Fields:
- `code`: Authorization code from Google
- `state`: State parameter for CSRF verification

#### `AccessTokenResponse`
Response containing the access token.

Fields:
- `access_token`: The ID token from Google
- `token_type`: Always "Bearer"
- `expires_in`: Token expiration in seconds

### Functions

#### `GoogleOAuthSecurityPlugin::init() -> Result<(), String>`
Initializes the OAuth configuration from environment variables.

#### `oauth_callback_handler(Json<OAuthCallbackRequest>) -> impl IntoResponse`
Handler for exchanging authorization code for tokens in the desktop flow. The user provides the code they copied from their browser.

## Testing

For testing without actual Google OAuth:

1. Use the `DefaultSecurityPlugin` for local development
2. Mock the OAuth endpoints using tools like WireMock
3. Use Google's OAuth 2.0 Playground for manual testing

## Troubleshooting

### "GOOGLE_CLIENT_ID environment variable not set"
- Ensure you've exported the environment variables before running the application
- Check for typos in variable names

### "Invalid token audience"
- Verify that the `GOOGLE_CLIENT_ID` matches the audience in the token
- Ensure you're using the correct client ID for your environment
- Make sure you created a "Desktop app" OAuth client, not a "Web application"

### "Token has expired"
- Tokens are time-limited; request a new token
- Check if system time is synchronized correctly

### "Failed to exchange code for token"
- Verify the authorization code hasn't been used already (codes are single-use)
- Ensure you copied the complete authorization code from the browser
- Check that client secret is correct
- Verify you're using a Desktop app OAuth client type in Google Cloud Console

## License

Apache License Version 2.0

See the [LICENSE](../LICENSE) file for details.
