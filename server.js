#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { z } from 'zod';
import { google } from 'googleapis';
import { Buffer } from 'buffer';

const logLevels = {
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3
};

class Logger {
  constructor(name) {
    this.name = name;
    this.logLevel = process.env.LOG_LEVEL ? 
      logLevels[(process.env.LOG_LEVEL || 'INFO').toUpperCase()] : 
      logLevels.INFO;
  }

  log(level, message) {
    if (logLevels[level] <= this.logLevel) {
      const timestamp = new Date().toISOString();
      console.error(`${timestamp} - ${this.name} - ${level} - ${message}`);
    }
  }

  info(message) { this.log('INFO', message); }
  warn(message) { this.log('WARN', message); }
  error(message) { this.log('ERROR', message); }
  debug(message) { this.log('DEBUG', message); }
}

const logger = new Logger('gmail-mcp');

class GmailClient {
  constructor() {
    const accessToken = process.env.GMAIL_ACCESS_TOKEN;
    if (!accessToken) {
      throw new Error('Access token must be provided via the GMAIL_ACCESS_TOKEN environment variable');
    }

    this.accessToken = accessToken;

    // Create the OAuth2 client
    this.oauth2Client = new google.auth.OAuth2();
    this.oauth2Client.setCredentials({ access_token: this.accessToken });

    // Create the Gmail API client with the OAuth2 client
    this.gmail = google.gmail({
      version: 'v1',
      auth: this.oauth2Client
    });
  }

  async _handleRequest(operation) {
    try {
      return await operation();
    } catch (error) {
      logger.error(`Request error: ${error.message}`);
      if (error.response) {
        const statusCode = error.response.status;
        return JSON.stringify({
          error: `Gmail API error: ${statusCode}`,
          details: error.message
        });
      }
      return JSON.stringify({
        error: 'Request to Gmail API failed',
        details: error.message
      });
    }
  }

  async getRecentEmails({ maxResults = 10, unreadOnly = false } = {}) {
    const operation = async () => {
      if (!this.gmail) {
        throw new Error('Gmail service not initialized. No valid access token provided.');
      }
      const query = unreadOnly ? 'is:unread' : '';
      const res = await this.gmail.users.messages.list({
        userId: 'me',
        maxResults,
        labelIds: ['INBOX'],
        q: query
      });
      const messages = res.data.messages || [];
      const emails = [];
      for (const message of messages) {
        const msg = await this.gmail.users.messages.get({
          userId: 'me',
          id: message.id,
          format: 'full'
        });
        const payload = msg.data.payload || {};
        const headers = (payload.headers || []).reduce((acc, h) => {
          const name = h.name.toLowerCase();
          if (['from', 'to', 'subject', 'date'].includes(name)) {
            acc[name] = h.value;
          }
          return acc;
        }, {});
        const { body, body_size_bytes, contains_full_body } = this.extractPlainTextBody(payload);
        emails.push({
          id: msg.data.id,
          threadId: msg.data.threadId,
          labelIds: msg.data.labelIds,
          snippet: msg.data.snippet,
          from: headers.from || '',
          to: headers.to || '',
          subject: headers.subject || '',
          date: headers.date || '',
          internalDate: msg.data.internalDate,
          body,
          body_size_bytes,
          contains_full_body
        });
      }
      return JSON.stringify({ emails });
    };
    return await this._handleRequest(operation);
  }

  extractPlainTextBody(payload) {
    let body = '';
    let body_size_bytes = 0;
    let contains_full_body = true;
    function extract(parts) {
      if (!parts) return;
      for (const part of parts) {
        if (part.mimeType === 'text/plain' && part.body && part.body.data) {
          const decoded = Buffer.from(part.body.data, 'base64').toString('utf-8');
          body += decoded;
          body_size_bytes += Buffer.byteLength(decoded);
        }
        if (part.parts) extract(part.parts);
      }
    }
    if (payload.body && payload.body.data) {
      const decoded = Buffer.from(payload.body.data, 'base64').toString('utf-8');
      body = decoded;
      body_size_bytes = Buffer.byteLength(decoded);
    }
    if (payload.parts) extract(payload.parts);
    if (body.length > 1000) {
      body = body.slice(0, 1000);
      contains_full_body = false;
    }
    return { body, body_size_bytes, contains_full_body };
  }

  async sendEmail({ to, subject, body, html_body }) {
    const operation = async () => {
      if (!this.gmail) {
        throw new Error('Gmail service not initialized. No valid access token provided.');
      }
      const messageParts = [
        `To: ${to}`,
        `Subject: ${subject}`,
        'Content-Type: multipart/alternative; boundary="boundary"',
        '',
        '--boundary',
        'Content-Type: text/plain; charset="UTF-8"',
        '',
        body,
        '--boundary',
        'Content-Type: text/html; charset="UTF-8"',
        '',
        html_body || '',
        '--boundary--'
      ];
      const rawMessage = Buffer.from(messageParts.join('\r\n')).toString('base64').replace(/\+/g, '-').replace(/\//g, '_');
      const res = await this.gmail.users.messages.send({
        userId: 'me',
        requestBody: { raw: rawMessage }
      });
      return JSON.stringify({
        messageId: res.data.id,
        threadId: res.data.threadId,
        labelIds: res.data.labelIds
      });
    };
    return await this._handleRequest(operation);
  }

  async getEmailBodyChunk({ message_id, thread_id, offset = 0 }) {
    const operation = async () => {
      if (!this.gmail) {
        throw new Error('Gmail service not initialized. No valid access token provided.');
      }
      let local_message_id = message_id;
      if (!local_message_id && thread_id) {
        const thread = await this.gmail.users.threads.get({ userId: 'me', id: thread_id });
        if (!thread.data.messages || !thread.data.messages.length) {
          return JSON.stringify({
            error: `No messages found in thread ${thread_id}`,
            status: 'error'
          });
        }
        local_message_id = thread.data.messages[0].id;
      }
      if (!local_message_id) {
        return JSON.stringify({
          error: 'Either message_id or thread_id must be provided',
          status: 'error'
        });
      }
      const msg = await this.gmail.users.messages.get({
        userId: 'me',
        id: local_message_id,
        format: 'full'
      });
      const payload = msg.data.payload || {};
      const { body, body_size_bytes } = this.extractPlainTextBody(payload);
      const chunk = offset >= body.length ? '' : body.slice(offset, offset + 1000);
      const contains_full_body = (offset + chunk.length >= body.length);
      return JSON.stringify({
        message_id: local_message_id,
        thread_id: msg.data.threadId,
        body: chunk,
        body_size_bytes,
        offset,
        chunk_size: chunk.length,
        contains_full_body,
        status: 'success'
      });
    };
    return await this._handleRequest(operation);
  }
}

async function main() {
  logger.info('Starting Gmail MCP server');
  try {
    const server = new McpServer({
      name: 'gmail-client',
      version: '0.1.0'
    });

    server.tool(
      'gmail_get_recent_emails',
      'Get the most recent emails from Gmail (returns metadata, snippets, and first 1k chars of body)',
      {
        max_results: z.number().optional().describe('Maximum number of emails to return (default: 10)'),
        unread_only: z.boolean().optional().describe('Whether to return only unread emails (default: False)')
      },
      async ({ max_results = 10, unread_only = false }) => {
        try {
          const gmail = new GmailClient();
          const result = await gmail.getRecentEmails({ maxResults: max_results, unreadOnly: unread_only });
          return { content: [{ type: 'text', text: result }] };
        } catch (error) {
          return { content: [{ type: 'text', text: `Error: ${error.message}` }] };
        }
      }
    );

    server.tool(
      'gmail_get_email_body_chunk',
      'Get a 1k character chunk of an email body starting from the specified offset',
      {
        message_id: z.string().optional().describe('ID of the message to retrieve'),
        thread_id: z.string().optional().describe('ID of the thread to retrieve (will get the first message if multiple exist)'),
        offset: z.number().optional().describe('Offset in characters to start from (default: 0)')
      },
      async ({ message_id, thread_id, offset = 0 }) => {
        try {
          const gmail = new GmailClient();
          const result = await gmail.getEmailBodyChunk({ message_id, thread_id, offset });
          return { content: [{ type: 'text', text: result }] };
        } catch (error) {
          return { content: [{ type: 'text', text: `Error: ${error.message}` }] };
        }
      }
    );

    server.tool(
      'gmail_send_email',
      'Send an email via Gmail',
      {
        to: z.string().describe('Recipient email address'),
        subject: z.string().describe('Email subject'),
        body: z.string().describe('Email body content (plain text)'),
        html_body: z.string().describe('Email body content in HTML format (optional)')
      },
      async ({ to, subject, body, html_body }) => {
        try {
          const gmail = new GmailClient();
          const result = await gmail.sendEmail({ to, subject, body, html_body });
          return { content: [{ type: 'text', text: result }] };
        } catch (error) {
          return { content: [{ type: 'text', text: `Error: ${error.message}` }] };
        }
      }
    );

    const transport = new StdioServerTransport();
    await server.connect(transport);
    logger.info('MCP server started and ready to receive requests');
  } catch (error) {
    logger.error(`Error starting server: ${error.message}`);
    process.exit(1);
  }
}

main();