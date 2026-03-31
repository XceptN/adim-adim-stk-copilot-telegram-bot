# Adım Adım STK Copilot Telegram Bot

A Telegram chatbot for [Adım Adım](https://www.adimadim.org/) NGO that integrates with Microsoft Copilot Studio to provide AI-powered support. The bot helps NGO staff and volunteers quickly get answers about charity runs and swimming competitions.

## Overview

This bot acts as a bridge between Telegram users and a Microsoft Copilot Studio agent. Users can ask questions via Telegram (text or images) and receive AI-generated responses in Turkish. The bot runs as an AWS Lambda function, making it cost-effective and highly scalable.

**Key capabilities:**
- Text and image message support
- Group chat support (responds to @mentions and replies)
- Persistent conversation context across messages via DynamoDB
- Automatic translation of English safety/refusal messages to Turkish
- Markdown-to-HTML conversion for rich Telegram formatting
- Webhook deduplication to handle Telegram retries gracefully

## Architecture

```
Telegram User
      │
      ▼
Telegram Bot API (webhook)
      │
      ▼
AWS Lambda (lambda_function.py)
      │
      ├── AWS DynamoDB (session storage)
      │
      └── Microsoft Copilot Studio (Direct Line API)
```

**Flow:**
1. Telegram delivers a webhook update to the Lambda function URL
2. Lambda validates, deduplicates, and extracts the message
3. The Direct Line session is loaded from DynamoDB (or a new one is created)
4. The message/image is posted to Copilot Studio via Direct Line API
5. Lambda polls for the AI response with exponential backoff
6. The response is converted from Markdown to Telegram HTML and sent back

## Requirements

- Python 3.x
- AWS account with Lambda and DynamoDB access
- Telegram bot token (from [@BotFather](https://t.me/BotFather))
- Microsoft Copilot Studio agent with Direct Line channel enabled

## Project Structure

```
.
├── lambda_function.py        # Main application — all bot logic
├── extract_conversations.sh  # CLI tool to extract conversations from CloudWatch logs
├── requirements.txt          # Python dependencies
└── LICENSE                   # GNU General Public License v3
```

## Deployment

### 1. Create the DynamoDB table

```bash
aws dynamodb create-table \
  --table-name adim-adim-bot-sessions \
  --attribute-definitions AttributeName=chat_id,AttributeType=S \
  --key-schema AttributeName=chat_id,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST \
  --time-to-live-specification Enabled=true,AttributeName=ttl
```

### 2. Create the Lambda function

- Runtime: **Python 3.12** (or any 3.x)
- Handler: `lambda_function.lambda_handler`
- Memory: 256 MB recommended
- Timeout: 180 seconds (the polling loop can take up to 120 s)

Package the function with its dependencies:

```bash
pip install -r requirements.txt -t .
zip -r lambda_package.zip . -x "*.git*" "extract_conversations.sh"
```

Upload `lambda_package.zip` to the Lambda function.

### 3. Configure environment variables

Set the following in the Lambda function's configuration:

| Variable | Required | Description |
|---|---|---|
| `TELEGRAM_BOT_TOKEN` | Yes | Token from BotFather |
| `DIRECTLINE_SECRET` | Yes | Copilot Studio Direct Line channel secret |
| `TELEGRAM_BOT_USERNAME` | Yes (groups) | Bot username without `@`, e.g. `AdimAdimBot` |
| `DYNAMODB_SESSION_TABLE` | Recommended | DynamoDB table name for session persistence |
| `TELEGRAM_SECRET_TOKEN` | Recommended | Secret for Telegram webhook signature validation |
| `REQUIRE_TG_SECRET` | No | Set to `"true"` to enforce webhook signature validation (default: `"false"`) |
| `DIRECTLINE_BASE_URL` | No | Direct Line base URL (default: `https://europe.directline.botframework.com`) |
| `DEFAULT_PROMPT` | No | Default Turkish prompt for image messages without caption |
| `AI_DISCLAIMER` | No | Optional text appended to every AI response |
| `LOGGING` | No | Log verbosity: `debug`, `info`, or `error` (default: `error`) |
| `DL_MAX_WAIT_SECONDS` | No | Max polling wait time in seconds (default: `120`) |
| `DL_INITIAL_POLL_INTERVAL` | No | Initial polling interval in seconds (default: `0.6`) |
| `DL_BACKOFF_FACTOR` | No | Exponential backoff multiplier (default: `1.9`) |
| `DL_MAX_POLL_INTERVAL` | No | Max polling interval in seconds (default: `17.0`) |
| `DL_TOKEN_TTL_SECONDS` | No | Direct Line token lifetime (default: `550`) |
| `DL_CONVERSATION_TTL_SECONDS` | No | Conversation idle timeout (default: `600`) |
| `CCI_BOT_ID` | No | Copilot Studio bot ID for token refresh |
| `CCI_TENANT_ID` | No | Azure tenant ID for token refresh |
| `CCI_ENVIRONMENT_ID` | No | Power Platform environment ID for token refresh |

### 4. Set up the Telegram webhook

Enable a Lambda Function URL (or API Gateway), then register it with Telegram:

```bash
curl -X POST "https://api.telegram.org/bot<TELEGRAM_BOT_TOKEN>/setWebhook" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://<your-lambda-url>",
    "secret_token": "<TELEGRAM_SECRET_TOKEN>"
  }'
```

### 5. Set Lambda permissions

The Lambda execution role needs:

```json
{
  "Effect": "Allow",
  "Action": [
    "dynamodb:GetItem",
    "dynamodb:PutItem",
    "dynamodb:UpdateItem",
    "dynamodb:DeleteItem"
  ],
  "Resource": "arn:aws:dynamodb:<region>:<account>:table/<DYNAMODB_SESSION_TABLE>"
}
```

## Bot Commands

| Command | Description |
|---|---|
| `/bot` | Reset the conversation and show the welcome message |
| `/yeni` | Alias for `/bot` — start a fresh conversation |

## Group Chat Behavior

The bot respects Telegram's **Group Privacy Mode**. When privacy mode is on (default), the bot only responds to:
- Direct @mentions: `@BotUsername sorum var`
- Replies to the bot's own messages
- The `/bot` and `/yeni` commands

When privacy mode is off, the bot responds to all messages in the group.

## Extracting Conversations

The `extract_conversations.sh` script fetches conversation logs from AWS CloudWatch:

```bash
# Last 7 days, short summary format
./extract_conversations.sh

# Last 1 day, full AI responses included
./extract_conversations.sh --full 1

# Custom date range (YYYY-MM-DD)
./extract_conversations.sh --full 2025-01-01 2025-01-31
```

**Prerequisites:** `aws` CLI, `jq`, and `python3` must be installed and the AWS CLI must be configured with CloudWatch Logs read access.

## Local Development

The Lambda handler can be invoked locally for testing by calling `lambda_handler` with a simulated Telegram webhook payload:

```python
import json
from lambda_function import lambda_handler

event = {
    "body": json.dumps({
        "update_id": 123456789,
        "message": {
            "message_id": 1,
            "chat": {"id": 111111111, "type": "private"},
            "from": {"id": 111111111, "first_name": "Test"},
            "text": "Merhaba",
            "date": 1700000000
        }
    }),
    "headers": {}
}

result = lambda_handler(event, {})
print(result)
```

Set `LOGGING=debug` in your environment to see verbose output during development.

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE) for details.

## Author

Özgür Yüksel
