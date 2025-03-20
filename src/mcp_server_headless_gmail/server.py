import logging
from typing import Any, Dict, List, Optional
import os
from dotenv import load_dotenv
from mcp.server.models import InitializationOptions
import mcp.types as types
from mcp.server import NotificationOptions, Server
import mcp.server.stdio
from pydantic import AnyUrl
import json
from datetime import datetime, timedelta
from dateutil.tz import tzlocal
import argparse
import base64
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import google.oauth2.credentials
import google.auth.exceptions

logger = logging.getLogger('mcp_server_headless_gmail')

def convert_datetime_fields(obj: Any) -> Any:
    """Convert any datetime or tzlocal objects to string in the given object"""
    if isinstance(obj, dict):
        return {k: convert_datetime_fields(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_datetime_fields(item) for item in obj]
    elif isinstance(obj, datetime):
        return obj.isoformat()
    elif isinstance(obj, tzlocal):
        # Get the current timezone offset
        offset = datetime.now(tzlocal()).strftime('%z')
        return f"UTC{offset[:3]}:{offset[3:]}"  # Format like "UTC+08:00" or "UTC-05:00"
    return obj

class GmailClient:
    def __init__(self, access_token: Optional[str] = None, refresh_token: Optional[str] = None, 
                 client_id: Optional[str] = None, client_secret: Optional[str] = None):
        if not refresh_token:
            raise ValueError("Refresh token is required")
        
        # Create credentials from the provided tokens
        self.credentials = google.oauth2.credentials.Credentials(
            token=access_token,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=client_id,
            client_secret=client_secret,
        )
        
        # Build the Gmail service if access token is provided
        if access_token:
            self.service = build('gmail', 'v1', credentials=self.credentials, cache_discovery=False)

    def _handle_token_refresh(self, func):
        """Decorator to handle token refresh errors gracefully"""
        try:
            return func()
        except google.auth.exceptions.RefreshError as e:
            logger.error(f"Token refresh error: {str(e)}")
            return json.dumps({
                "error": "Token refresh failed. Please provide new access and refresh tokens.",
                "details": str(e)
            })

    def refresh_token(self, client_id: str, client_secret: str) -> str:
        """Refresh the access token using the refresh token
        
        Args:
            client_id: Google OAuth2 client ID
            client_secret: Google OAuth2 client secret
        """
        try:
            # Set client_id and client_secret for refresh
            self.credentials._client_id = client_id
            self.credentials._client_secret = client_secret
            
            # Force refresh
            self.credentials.refresh(None)
            
            # Get token expiration time
            expiry = self.credentials.expiry
            
            # Return the new access token and its expiration
            return json.dumps({
                "access_token": self.credentials.token,
                "expires_at": expiry.isoformat() if expiry else None,
                "expires_in": int((expiry - datetime.now(expiry.tzinfo)).total_seconds()) if expiry else None,
                "status": "success"
            })
            
        except google.auth.exceptions.RefreshError as e:
            logger.error(f"Token refresh error: {str(e)}")
            return json.dumps({
                "error": "Token refresh failed. Please provide valid client ID and client secret.",
                "details": str(e),
                "status": "error"
            })
        except Exception as e:
            logger.error(f"Exception: {str(e)}")
            return json.dumps({
                "error": str(e),
                "status": "error"
            })

    def get_recent_emails(self, max_results: int = 10) -> str:
        """Get the most recent emails from Gmail
        
        Args:
            max_results: Maximum number of emails to return (default: 10)
        """
        try:
            # Check if service is initialized
            if not hasattr(self, 'service'):
                return json.dumps({
                    "error": "No valid access token provided. Please refresh your token first.",
                    "status": "error"
                })
                
            # Define the operation
            def _operation():
                # Get list of recent messages
                response = self.service.users().messages().list(
                    userId='me',
                    maxResults=max_results,
                    labelIds=['INBOX'],
                    q='is:unread'  # Get unread messages by default
                ).execute()
                
                messages = response.get('messages', [])
                
                if not messages:
                    return json.dumps({"emails": []})
                
                # Fetch detailed information for each message
                emails = []
                for message in messages:
                    msg = self.service.users().messages().get(
                        userId='me',
                        id=message['id'],
                        format='full'
                    ).execute()
                    
                    # Extract headers
                    headers = {}
                    if 'payload' in msg and 'headers' in msg['payload']:
                        for header in msg['payload']['headers']:
                            name = header.get('name', '').lower()
                            if name in ['from', 'to', 'subject', 'date']:
                                headers[name] = header.get('value', '')
                    
                    # Extract message body
                    body = ""
                    if 'payload' in msg:
                        if 'body' in msg['payload'] and 'data' in msg['payload']['body']:
                            body = base64.urlsafe_b64decode(msg['payload']['body']['data']).decode('utf-8')
                        elif 'parts' in msg['payload']:
                            for part in msg['payload']['parts']:
                                if part['mimeType'] == 'text/plain' and 'body' in part and 'data' in part['body']:
                                    body = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8')
                                    break
                    
                    # Format the email
                    email_data = {
                        "id": msg['id'],
                        "threadId": msg['threadId'],
                        "labelIds": msg.get('labelIds', []),
                        "snippet": msg.get('snippet', ''),
                        "from": headers.get('from', ''),
                        "to": headers.get('to', ''),
                        "subject": headers.get('subject', ''),
                        "date": headers.get('date', ''),
                        "body": body,
                        "internalDate": msg.get('internalDate', '')
                    }
                    
                    emails.append(email_data)
                
                return json.dumps({"emails": convert_datetime_fields(emails)})
            
            # Execute the operation with token refresh handling
            return self._handle_token_refresh(_operation)
            
        except HttpError as e:
            logger.error(f"API Exception: {str(e)}")
            return json.dumps({"error": str(e)})
        except Exception as e:
            logger.error(f"Exception: {str(e)}")
            return json.dumps({"error": str(e)})
    
    def send_email(self, to: str, subject: str, body: str, html_body: Optional[str] = None) -> str:
        """Send an email via Gmail
        
        Args:
            to: Recipient email address
            subject: Email subject
            body: Plain text email body
            html_body: Optional HTML email body
        """
        try:
            # Check if service is initialized
            if not hasattr(self, 'service'):
                return json.dumps({
                    "error": "No valid access token provided. Please refresh your token first.",
                    "status": "error"
                })
                
            # Define the operation
            def _operation():
                # Create message container
                message = MIMEMultipart('alternative')
                message['to'] = to
                message['subject'] = subject
                
                # Attach plain text and HTML parts
                message.attach(MIMEText(body, 'plain'))
                if html_body:
                    message.attach(MIMEText(html_body, 'html'))
                
                # Encode the message
                encoded_message = base64.urlsafe_b64encode(message.as_bytes()).decode()
                
                # Create the message body
                create_message = {
                    'raw': encoded_message
                }
                
                # Send the message
                send_response = self.service.users().messages().send(
                    userId='me', 
                    body=create_message
                ).execute()
                
                return json.dumps({
                    "messageId": send_response['id'],
                    "threadId": send_response.get('threadId', ''),
                    "labelIds": send_response.get('labelIds', [])
                })
            
            # Execute the operation with token refresh handling
            return self._handle_token_refresh(_operation)
            
        except HttpError as e:
            logger.error(f"API Exception: {str(e)}")
            return json.dumps({"error": str(e)})
        except Exception as e:
            logger.error(f"Exception: {str(e)}")
            return json.dumps({"error": str(e)})

async def main():
    """Run the Gmail MCP server."""
    logger.info("Gmail server starting")
    server = Server("gmail-client")

    @server.list_resources()
    async def handle_list_resources() -> list[types.Resource]:
        return []

    @server.read_resource()
    async def handle_read_resource(uri: AnyUrl) -> str:
        if uri.scheme != "gmail":
            raise ValueError(f"Unsupported URI scheme: {uri.scheme}")

        path = str(uri).replace("gmail://", "")
        return ""

    @server.list_tools()
    async def handle_list_tools() -> list[types.Tool]:
        """List available tools"""
        return [
            types.Tool(
                name="gmail_refresh_token",
                description="Refresh the access token using the refresh token and client credentials",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "google_access_token": {"type": "string", "description": "Google OAuth2 access token (optional if expired)"},
                        "google_refresh_token": {"type": "string", "description": "Google OAuth2 refresh token"},
                        "google_client_id": {"type": "string", "description": "Google OAuth2 client ID for token refresh"},
                        "google_client_secret": {"type": "string", "description": "Google OAuth2 client secret for token refresh"}
                    },
                    "required": ["google_refresh_token", "google_client_id", "google_client_secret"]
                },
            ),
            types.Tool(
                name="gmail_get_recent_emails",
                description="Get the most recent emails from Gmail",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "google_access_token": {"type": "string", "description": "Google OAuth2 access token"},
                        "google_refresh_token": {"type": "string", "description": "Google OAuth2 refresh token"},
                        "max_results": {"type": "integer", "description": "Maximum number of emails to return (default: 10)"}
                    },
                    "required": ["google_access_token", "google_refresh_token"]
                },
            ),
            types.Tool(
                name="gmail_send_email",
                description="Send an email via Gmail",
                inputSchema={
                    "type": "object",
                    "properties": {
                        "google_access_token": {"type": "string", "description": "Google OAuth2 access token"},
                        "google_refresh_token": {"type": "string", "description": "Google OAuth2 refresh token"},
                        "to": {"type": "string", "description": "Recipient email address"},
                        "subject": {"type": "string", "description": "Email subject"},
                        "body": {"type": "string", "description": "Email body content (plain text)"},
                        "html_body": {"type": "string", "description": "Email body content in HTML format (optional)"}
                    },
                    "required": ["google_access_token", "google_refresh_token", "to", "subject", "body"]
                },
            ),
        ]

    @server.call_tool()
    async def handle_call_tool(
        name: str, arguments: dict[str, Any] | None
    ) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
        """Handle tool execution requests"""
        try:
            if not arguments:
                raise ValueError(f"Missing arguments for {name}")
            
            if name == "gmail_refresh_token":
                # For refresh token, we need refresh token, client ID and secret
                refresh_token = arguments.get("google_refresh_token")
                client_id = arguments.get("google_client_id")
                client_secret = arguments.get("google_client_secret")
                access_token = arguments.get("google_access_token")  # Optional for refresh
                
                if not refresh_token:
                    raise ValueError("google_refresh_token is required for token refresh")
                
                if not client_id or not client_secret:
                    raise ValueError("Both google_client_id and google_client_secret are required for token refresh")
                
                # Initialize Gmail client for token refresh
                gmail = GmailClient(
                    access_token=access_token, 
                    refresh_token=refresh_token
                )
                
                # Call the refresh_token method
                results = gmail.refresh_token(client_id=client_id, client_secret=client_secret)
                return [types.TextContent(type="text", text=results)]
            
            else:
                # For all other tools, we need both access and refresh tokens
                access_token = arguments.get("google_access_token")
                refresh_token = arguments.get("google_refresh_token")
                
                if not access_token or not refresh_token:
                    raise ValueError("Both google_access_token and google_refresh_token are required")
                
                if name == "gmail_get_recent_emails":
                    # Initialize Gmail client with just tokens
                    gmail = GmailClient(
                        access_token=access_token, 
                        refresh_token=refresh_token
                    )
                    
                    max_results = int(arguments.get("max_results", 10))
                    results = gmail.get_recent_emails(max_results=max_results)
                    return [types.TextContent(type="text", text=results)]
                    
                elif name == "gmail_send_email":
                    # Initialize Gmail client with just tokens
                    gmail = GmailClient(
                        access_token=access_token, 
                        refresh_token=refresh_token
                    )
                    
                    to = arguments.get("to")
                    subject = arguments.get("subject")
                    body = arguments.get("body")
                    html_body = arguments.get("html_body")
                    
                    if not to or not subject or not body:
                        raise ValueError("Missing required parameters: to, subject, and body are required")
                    
                    results = gmail.send_email(to=to, subject=subject, body=body, html_body=html_body)
                    return [types.TextContent(type="text", text=results)]

                else:
                    raise ValueError(f"Unknown tool: {name}")

        except Exception as e:
            return [types.TextContent(type="text", text=f"Error: {str(e)}")]

    async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
        logger.info("Server running with stdio transport")
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="gmail",
                server_version="0.1.0",
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    import asyncio
    
    # Simplified command-line with no OAuth parameters
    asyncio.run(main()) 