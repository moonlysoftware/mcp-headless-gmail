# MCP Headless Gmail Server

This is a simple MCP (Multi-Agent Conversation Protocol) server that provides Gmail API functionality. This server allows you to interact with Gmail through MCP-compatible clients.

## Why MCP Headless Gmail Server?
### Critical Advantages
- **Headless & Remote Operation**: Unlike other Gmail solutions that require a login page and local file access, this server can run completely headless in remote environments.
- **Decoupled Architecture**: Any application can complete the OAuth flow independently, then pass credentials as context to this MCP server, creating a complete separation between credential storage and server implementation.

### Nice but not critical
- **Focused Functionality**: In many use cases, especially for marketing applications, only Gmail access is needed without additional Google services like Calendar, making this focused implementation ideal.
- **Docker-Ready**: Designed with containerization in mind for a well-isolated, environment-independent, one-click setup.
- **Reliable Dependencies**: Built on the well-maintained google-api-python-client library.

## Features

- Get most recent emails from Gmail
- Send emails through Gmail
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

## Usage

The server provides Gmail functionality through MCP tools. All authentication is handled through the tool parameters.

### Starting the Server

```bash
mcp-server-headless-gmail
```

### Using the Tools

When using an MCP client like Claude, you need to provide your Google API credentials with each tool call:

#### Getting Recent Emails

```json
{
  "google_access_token": "your_access_token",
  "google_refresh_token": "your_refresh_token",
  "google_client_id": "your_client_id",
  "google_client_secret": "your_client_secret",
  "max_results": 5
}
```

#### Sending an Email

```json
{
  "google_access_token": "your_access_token",
  "google_refresh_token": "your_refresh_token",
  "google_client_id": "your_client_id",
  "google_client_secret": "your_client_secret",
  "to": "recipient@example.com",
  "subject": "Hello from MCP Gmail",
  "body": "This is a test email sent via MCP Gmail server",
  "html_body": "<p>This is a <strong>test email</strong> sent via MCP Gmail server</p>"
}
```

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
