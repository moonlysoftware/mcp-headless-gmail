# MCP Headless Gmail Server

A MCP (Model Context Protocol) server that provides get, send Gmails without local credential or token setup.

## Why MCP Headless Gmail Server?
### Critical Advantages
- **Headless & Remote Operation**: Unlike other MCP Gmail solutions that require running outside of docker and local file access, this server can run completely headless in remote environments with no browser no local file access.
- **Decoupled Architecture**: Any client can complete the OAuth flow independently, then pass credentials as context to this MCP server, creating a complete separation between credential storage and server implementation.

### Nice but not critical
- **Focused Functionality**: In many use cases, especially for marketing applications, only Gmail access is needed without additional Google services like Calendar, making this focused implementation ideal.
- **Docker-Ready**: Designed with containerization in mind for a well-isolated, environment-independent, one-click setup.
- **Reliable Dependencies**: Built on the well-maintained google-api-python-client library.

## Features

- Get most recent emails from Gmail
- Send emails through Gmail
- Refresh access tokens separately
- Automatic refresh token handling

## Prerequisites

- Python 3.10 or higher
- Google API credentials (client ID, client secret, access token, and refresh token)

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/mcp-headless-gmail.git
cd mcp-headless-gmail

# Install dependencies
pip install -e .
```

## Docker

### Building the Docker Image

```bash
# Build the Docker image
docker build -t mcp-headless-gmail .
```

## Usage with Claude Desktop

### Docker Usage

You can configure Claude Desktop to use the Docker image by adding the following to your Claude configuration:

```json
{
  "mcpServers": {
    "gmail": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "buryhuang/mcp-headless-gmail:latest"
      ]
    }
  }
}
```

Note: With this configuration, you'll need to provide your Google API credentials in the tool calls as shown in the [Using the Tools](#using-the-tools) section. Gmail credentials are not passed as environment variables to maintain separation between credential storage and server implementation.

## Cross-Platform Publishing

To publish the Docker image for multiple platforms, you can use the `docker buildx` command. Follow these steps:

1. **Create a new builder instance** (if you haven't already):
   ```bash
   docker buildx create --use
   ```

2. **Build and push the image for multiple platforms**:
   ```bash
   docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7 -t buryhuang/mcp-headless-gmail:latest --push .
   ```

3. **Verify the image is available for the specified platforms**:
   ```bash
   docker buildx imagetools inspect buryhuang/mcp-headless-gmail:latest
   ```

## Usage

The server provides Gmail functionality through MCP tools. Authentication handling is simplified with a dedicated token refresh tool.

### Starting the Server

```bash
mcp-server-headless-gmail
```

### Using the Tools

When using an MCP client like Claude, you have two main ways to handle authentication:

#### Refreshing Tokens (First Step or When Tokens Expire)

If you have both access and refresh tokens:
```json
{
  "google_access_token": "your_access_token",
  "google_refresh_token": "your_refresh_token",
  "google_client_id": "your_client_id",
  "google_client_secret": "your_client_secret"
}
```

If your access token has expired, you can refresh with just the refresh token:
```json
{
  "google_refresh_token": "your_refresh_token",
  "google_client_id": "your_client_id",
  "google_client_secret": "your_client_secret"
}
```

This will return a new access token and its expiration time, which you can use for subsequent calls.

#### Getting Recent Emails

With the new implementation, you only need to provide the access token and refresh token for most calls:

```json
{
  "google_access_token": "your_access_token",
  "google_refresh_token": "your_refresh_token",
  "max_results": 5
}
```

#### Sending an Email

Similarly, sending emails also doesn't require client credentials for every call:

```json
{
  "google_access_token": "your_access_token",
  "google_refresh_token": "your_refresh_token",
  "to": "recipient@example.com",
  "subject": "Hello from MCP Gmail",
  "body": "This is a test email sent via MCP Gmail server",
  "html_body": "<p>This is a <strong>test email</strong> sent via MCP Gmail server</p>"
}
```

### Token Refresh Workflow

1. Start by calling the `gmail_refresh_token` tool with either:
   - Your full credentials (access token, refresh token, client ID, and client secret), or
   - Just your refresh token, client ID, and client secret if the access token has expired
2. Use the returned new access token for subsequent `gmail_get_recent_emails` and `gmail_send_email` calls.
3. If you get a response indicating token expiration, call the `gmail_refresh_token` tool again to get a new token.

This approach simplifies most API calls by not requiring client credentials for every operation, while still enabling token refresh when needed.

## Obtaining Google API Credentials

To obtain the required Google API credentials, follow these steps:

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project
3. Enable the Gmail API
4. Configure OAuth consent screen
5. Create OAuth client ID credentials (select "Desktop app" as the application type)
6. Save the client ID and client secret
7. Use OAuth 2.0 to obtain access and refresh tokens with the following scopes:
   - `https://www.googleapis.com/auth/gmail.readonly` (for reading emails)
   - `https://www.googleapis.com/auth/gmail.send` (for sending emails)

## Token Refreshing

This server implements automatic token refreshing. When your access token expires, the Google API client will use the refresh token, client ID, and client secret to obtain a new access token without requiring user intervention.

## Security Note

This server requires direct access to your Google API credentials. Always keep your tokens and credentials secure and never share them with untrusted parties.

## License

See the LICENSE file for details. 
