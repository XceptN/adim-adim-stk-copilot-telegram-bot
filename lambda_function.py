# lambda_function.py for Adım Adım STK Telegram Bot with Copilot Studio integration
# Author: Özgür Yüksel

import base64
import boto3
import json
import mimetypes
import os
import time
import urllib.request
import urllib.parse
import urllib.error
import uuid
import random
import re
from datetime import datetime, timezone
from wsgiref import headers

TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
REQUIRE_TG_SECRET  = os.environ.get("REQUIRE_TG_SECRET", "false").lower() == "true"
LOGGING = os.environ.get("LOGGING", "error").lower() # debug, info, error

TELEGRAM_SECRET_TOKEN = os.environ.get("TELEGRAM_SECRET_TOKEN", "")
DIRECTLINE_SECRET  = os.environ["DIRECTLINE_SECRET"]
DIRECTLINE_BASE_URL = os.environ.get("DIRECTLINE_BASE_URL", "https://europe.directline.botframework.com")
DEFAULT_PROMPT = os.environ.get("DEFAULT_PROMPT", "Bu ekran görüntüsündeki problemi nasıl çözebilirim?")
AI_DISCLAIMER = os.environ.get("AI_DISCLAIMER")

# Bot username (without @) - needed for group mention detection
# Set this in Lambda environment variables, e.g., "AdimAdimSTKBot"
TELEGRAM_BOT_USERNAME = os.environ.get("TELEGRAM_BOT_USERNAME", "")

# ---- Tuning knobs for polling patience ----
DL_MAX_WAIT_SECONDS = float(os.environ.get("DL_MAX_WAIT_SECONDS", "120"))
DL_INITIAL_POLL_INTERVAL = float(os.environ.get("DL_INITIAL_POLL_INTERVAL", "0.6"))
DL_BACKOFF_FACTOR = float(os.environ.get("DL_BACKOFF_FACTOR", "1.9"))
DL_MAX_POLL_INTERVAL = float(os.environ.get("DL_MAX_POLL_INTERVAL", "17.0"))

# ---- DynamoDB Session Persistence ----
# Set DYNAMODB_SESSION_TABLE in Lambda env vars (e.g., "copilot-telegram-sessions")
DYNAMODB_SESSION_TABLE = os.environ.get("DYNAMODB_SESSION_TABLE", "")
# Direct Line tokens expire in ~10 min; refresh a bit earlier
DL_TOKEN_TTL_SECONDS = int(os.environ.get("DL_TOKEN_TTL_SECONDS", "550")) 
# How long to keep a conversation alive (idle timeout)
DL_CONVERSATION_TTL_SECONDS = int(os.environ.get("DL_CONVERSATION_TTL_SECONDS", "600"))

# Lazy-init DynamoDB resource
_dynamo_table = None

def _get_session_table():
    global _dynamo_table
    if _dynamo_table is None and DYNAMODB_SESSION_TABLE:
        dynamodb = boto3.resource("dynamodb")
        _dynamo_table = dynamodb.Table(DYNAMODB_SESSION_TABLE)
    return _dynamo_table


def session_load(session_key):
    """Load an existing Direct Line session for this Telegram chat_id."""
    table = _get_session_table()
    if not table:
        debug_print("[SESSION] No DynamoDB table configured – sessions disabled")
        return None
    try:
        resp = table.get_item(Key={"session_key": session_key})
        item = resp.get("Item")
        if not item:
            debug_print(f"[SESSION] No existing session for session_key={session_key}")
            return None
        # Check if expired
        expires_at = float(item.get("expires_at", 0))
        if time.time() > expires_at:
            debug_print(f"[SESSION] Session expired for session_key={session_key}")
            return None
        debug_print(f"[SESSION] Loaded session for session_key={session_key} conv_id={item.get('conversation_id')}")
        return item
    except Exception as ex:
        error_print(f"[SESSION] Load error: {ex}")
        return None


def session_save(session_key, token, conversation_id, watermark=None):
    """Save / update a Direct Line session for this Telegram session_key."""
    table = _get_session_table()
    if not table:
        return
    try:
        now = time.time()
        item = {
            "session_key": str(session_key),
            "token": token,
            "conversation_id": conversation_id,
            "watermark": watermark or "",
            "expires_at": int(now + DL_CONVERSATION_TTL_SECONDS),
            "token_expires_at": int(now + DL_TOKEN_TTL_SECONDS),
            "updated_at": int(now),
            # TTL attribute for DynamoDB auto-cleanup (set generously)
            "ttl": int(now + DL_CONVERSATION_TTL_SECONDS + 3600),
        }
        table.put_item(Item=item)
        debug_print(f"[SESSION] Saved session session_key={session_key} conv_id={conversation_id}")
    except Exception as ex:
        error_print(f"[SESSION] Save error: {ex}")


def dedup_check_and_lock(update_id):
    """
    Attempt to claim this Telegram update_id so only one Lambda processes it.
    Returns True if we got the lock (first time), False if already seen (retry).
    Uses a conditional PutItem so only one concurrent invocation wins.
    """
    table = _get_session_table()
    if not table:
        # No DynamoDB table -> no dedup possible, process anyway
        return True
    dedup_key = f"dedup:{update_id}"
    try:
        table.put_item(
            Item={
                "session_key": dedup_key,
                "created_at": int(time.time()),
                "ttl": int(time.time()) + 300,  # auto-cleanup after 5 min
            },
            ConditionExpression="attribute_not_exists(session_key)",
        )
        debug_print(f"[DEDUP] Claimed update_id={update_id}")
        return True
    except table.meta.client.exceptions.ConditionalCheckFailedException:
        debug_print(f"[DEDUP] Duplicate update_id={update_id} -> skipping")
        return False
    except Exception as ex:
        error_print(f"[DEDUP] Error: {ex} -> processing anyway")
        return True  # Fail-open: process if DynamoDB errors


def session_delete(session_key):
    """Delete a session (e.g., on /bot , /yeni to force fresh conversation)."""
    table = _get_session_table()
    if not table:
        return
    try:
        table.delete_item(Key={"session_key": str(session_key)})
        debug_print(f"[SESSION] Deleted session for session_key={session_key}")
    except Exception as ex:
        error_print(f"[SESSION] Delete error: {ex}")


def debug_print(*args, **kwargs):
    if LOGGING == "debug":
        print("[DEBUG]", *args, **kwargs)

def info_print(*args, **kwargs):
    if LOGGING in ("debug", "info"):
        print("[INFO]", *args, **kwargs)

def error_print(*args, **kwargs):
    if LOGGING in ("debug", "info", "error"):
        print("[ERROR]", *args, **kwargs)


# -------- Helpers: HTTP --------
def http_get(url, headers=None, timeout=90):
    debug_print(f"[HTTP][GET] url={url} headers={_redact_headers(headers)} timeout={timeout}")
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        debug_print(f"[HTTP][GET][{url}] status={resp.status} len={len(data)}")
        return data, resp.getcode(), dict(resp.headers)

def http_get_json(url, headers=None, timeout=90):
    h = dict(headers or {})
    if "Accept" not in {k.title(): v for k, v in h.items()}:
        h["Accept"] = "application/json"
    return http_get(url, headers=h, timeout=timeout)

def http_post_json(url, payload, headers=None, timeout=90):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    body = json.dumps(payload).encode("utf-8")
    debug_print(f"[HTTP][POST-JSON] url={url} headers={_redact_headers(h)} bytes={len(body)}")
    req = urllib.request.Request(url, data=body, headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        debug_print(f"[HTTP][POST-JSON][{url}] status={resp.status} len={len(data)}")
        return data, resp.getcode(), dict(resp.headers)

def http_post_multipart_copilot(url, activity_json, file_name, file_content, file_content_type, headers=None, timeout=90):
    """
    Copilot Studio'nun EXACT beklediği multipart format:
    - activity part: name="activity", filename="blob", Content-Type: application/vnd.microsoft.activity
    - file part: name="file", filename="xxx.jpg", Content-Type: image/jpeg
    """
    boundary = f"----WebKitFormBoundary{uuid.uuid4().hex}"
    
    debug_print(f"[HTTP][POST-COPILOT] url={url} boundary={boundary} file={file_name}")
    
    CRLF = b"\r\n"
    body_parts = []
    
    # Part 1: activity - EXACT Copilot format
    body_parts.append(f"--{boundary}".encode())
    body_parts.append(b'Content-Disposition: form-data; name="activity"; filename="blob"')
    body_parts.append(b'Content-Type: application/vnd.microsoft.activity')
    body_parts.append(b'')  # Empty line between headers and content
    body_parts.append(activity_json.encode('utf-8'))
    
    # Part 2: file
    body_parts.append(f"--{boundary}".encode())
    body_parts.append(f'Content-Disposition: form-data; name="file"; filename="{file_name}"'.encode())
    body_parts.append(f'Content-Type: {file_content_type}'.encode())
    body_parts.append(b'')
    body_parts.append(file_content)
    
    # Final boundary
    body_parts.append(f"--{boundary}--".encode())
    
    data = CRLF.join(body_parts)
    
    h = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(data))
    }
    if headers:
        h.update(headers)
    
    debug_print(f"[HTTP][POST-COPILOT] total_bytes={len(data)}")
    
    # Debug: Show first 1500 chars (excluding binary image data)
    debug_preview = data[:1500].decode('utf-8', errors='replace')
    debug_print(f"[HTTP][POST-COPILOT] body_preview:\n{debug_preview}")
    
    try:
        req = urllib.request.Request(url, data=data, headers=h, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            rdata = resp.read()
            debug_print(f"[HTTP][POST-COPILOT] status={resp.status} response={rdata.decode('utf-8', errors='replace')[:500]}")
            return rdata, resp.getcode(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        err_body = e.read()
        debug_print(f"[HTTP][POST-COPILOT][ERR] status={e.code} body={err_body}")
        return err_body, e.code, dict(e.headers or {})

def _redact_headers(h):
    if not h: return {}
    redacted = {}
    for k, v in h.items():
        if k.lower() == "authorization":
            redacted[k] = v[:15] + "...(redacted)"
        else:
            redacted[k] = v
    return redacted

# -------- Helpers: Telegram --------
def strip_citation_lines(text):
    """Remove lines that contain citation markers like 'Citation-' and citation references in [ ]."""
    import re
    cleaned = re.sub(r'^.*Citation-.*$\n?', '', text, flags=re.MULTILINE)
    # Remove single digit numbers at the end of lines
    cleaned = re.sub(r'\[\d\]', '', cleaned, flags=re.MULTILINE)
    return cleaned.strip()

def markdown_to_telegram_html(text):
    """
    Convert standard Markdown (as returned by Copilot Studio) to Telegram-safe HTML.
    
    Handles: **bold**, __bold__, *italic*, _italic_, `code`, ```code blocks```,
             [link text](url), ~~strikethrough~~
    
    Telegram HTML supports: <b>, <i>, <code>, <pre>, <a href="">, <s>
    """
    # First, escape HTML special chars in the raw text
    # We'll do this carefully to not break our own tags later
    
    # Step 1: Extract code blocks and inline code to protect them
    protected = {}
    counter = [0]
    
    def protect(match):
        key = f"\x00PROTECTED{counter[0]}\x00"
        counter[0] += 1
        protected[key] = match.group(0)
        return key
    
    # Protect fenced code blocks first (```...```)
    result = re.sub(r'```([\s\S]*?)```', protect, text)
    # Protect inline code (`...`)
    result = re.sub(r'`([^`]+)`', protect, result)
    
    # Step 2: Escape HTML entities in unprotected text
    result = result.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
    
    # Step 3: Convert Markdown formatting to HTML
    # Headings: ### h3, ## h2, # h1 -> bold (Telegram has no heading tags)
    # Process in order: ### before ## before # to avoid partial matches
    result = re.sub(r'^###\s+(.+)$', r'<b>\1</b>', result, flags=re.MULTILINE)
    result = re.sub(r'^##\s+(.+)$', r'<b>\1</b>', result, flags=re.MULTILINE)
    result = re.sub(r'^#\s+(.+)$', r'<b>\1</b>', result, flags=re.MULTILINE)
    
    # Bullet points: - item -> • item
    result = re.sub(r'^- ', '• ', result, flags=re.MULTILINE)
    
    # Links: [text](url) -> <a href="url">text</a>
    result = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'<a href="\2">\1</a>', result)
    
    # Bold: **text** or __text__  -> <b>text</b>
    result = re.sub(r'\*\*(.+?)\*\*', r'<b>\1</b>', result)
    result = re.sub(r'__(.+?)__', r'<b>\1</b>', result)
    
    # Italic: *text* or _text_ -> <i>text</i>
    # Be careful not to match underscores within words (e.g. variable_name)
    result = re.sub(r'(?<!\w)\*([^\*]+?)\*(?!\w)', r'<i>\1</i>', result)
    result = re.sub(r'(?<!\w)_([^_]+?)_(?!\w)', r'<i>\1</i>', result)
    
    # Strikethrough: ~~text~~ -> <s>text</s>
    result = re.sub(r'~~(.+?)~~', r'<s>\1</s>', result)
    
    # Step 4: Restore protected code blocks with HTML tags
    for key, original in protected.items():
        if original.startswith('```'):
            code_content = original[3:-3].strip()
            # Escape HTML inside code
            code_content = code_content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            replacement = f'<pre>{code_content}</pre>'
        else:
            code_content = original[1:-1]
            code_content = code_content.replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')
            replacement = f'<code>{code_content}</code>'
        result = result.replace(key, replacement)
    
    return result


def strip_markdown(text):
    """Remove Markdown formatting entirely for plain text fallback."""
    # Remove headings markers
    result = re.sub(r'^###\s+', '', text, flags=re.MULTILINE)
    result = re.sub(r'^##\s+', '', result, flags=re.MULTILINE)
    result = re.sub(r'^#\s+', '', result, flags=re.MULTILINE)
    # Bullet points: - item -> • item
    result = re.sub(r'^- ', '• ', result, flags=re.MULTILINE)
    # Remove fenced code block markers
    result = re.sub(r'```[\s\S]*?```', lambda m: m.group(0)[3:-3].strip(), text)
    # Remove inline code markers
    result = re.sub(r'`([^`]+)`', r'\1', result)
    # Convert links to "text (url)" format
    result = re.sub(r'\[([^\]]+)\]\(([^)]+)\)', r'\1 (\2)', result)
    # Remove bold/italic markers
    result = re.sub(r'\*\*(.+?)\*\*', r'\1', result)
    result = re.sub(r'__(.+?)__', r'\1', result)
    result = re.sub(r'(?<!\w)\*([^\*]+?)\*(?!\w)', r'\1', result)
    result = re.sub(r'(?<!\w)_([^_]+?)_(?!\w)', r'\1', result)
    result = re.sub(r'~~(.+?)~~', r'\1', result)
    return result


def tg_send_message(chat_id, text, reply_to_message_id=None):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"

    text = strip_citation_lines(text)

    # Strategy: try HTML (most reliable with formatting) -> plain text fallback
    html_text = markdown_to_telegram_html(text)
    payload = {"chat_id": chat_id, "text": html_text, "parse_mode": "HTML"}
    if reply_to_message_id:
        payload["reply_to_message_id"] = reply_to_message_id

    try:
        _, code, _ = http_post_json(url, payload)
        debug_print(f"[TG] sendMessage (HTML) status={code}")
        if code == 200:
            info_print(f"[TG] Message sent to user: <{text}>")
            return True
    except urllib.error.HTTPError as e:
        debug_print(f"[TG] sendMessage HTML failed ({e.code}), falling back to plain text")

    # Fallback: send as plain text (strip all formatting)
    plain_text = strip_markdown(text)
    payload_plain = {"chat_id": chat_id, "text": plain_text}
    if reply_to_message_id:
        payload_plain["reply_to_message_id"] = reply_to_message_id

    try:
        _, code, _ = http_post_json(url, payload_plain)
        debug_print(f"[TG] sendMessage (plain) status={code}")
        info_print(f"[TG] Message sent to user: <{text}>")
        return code == 200
    except urllib.error.HTTPError as e:
        error_print(f"[TG] sendMessage plain text also failed: {e.code}")
        return False

def tg_send_photo_by_url(chat_id, url_or_fileid, caption=None, reply_to_message_id=None):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendPhoto"
    payload = {"chat_id": chat_id, "photo": url_or_fileid}
    if caption:
        payload["caption"] = caption
    if reply_to_message_id:
        payload["reply_to_message_id"] = reply_to_message_id
    debug_print(f"[TG] sendPhoto chat_id={chat_id} source={'url/fileid'} caption_len={len(caption or '')} reply_to={reply_to_message_id}")
    _, code, _ = http_post_json(url, payload)
    debug_print(f"[TG] sendPhoto status={code}")
    return code == 200

def tg_send_chat_action(chat_id, action="typing"):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendChatAction"
    payload = {"chat_id": chat_id, "action": action}
    _, code, _ = http_post_json(url, payload)
    debug_print(f"[TG] sendChatAction action={action} status={code}")
    return code == 200

def tg_get_file(file_id):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getFile?file_id={urllib.parse.quote(file_id)}"
    debug_print(f"[TG] getFile file_id={file_id}")
    body, code, _ = http_get(url)
    if code != 200:
        raise RuntimeError(f"getFile failed: {code} {body}")
    obj = json.loads(body.decode())
    if not obj.get("ok"):
        raise RuntimeError(f"getFile not ok: {obj}")
    file_path = obj["result"]["file_path"]
    download_url = f"https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_path}"
    debug_print(f"[TG] getFile ok file_path={file_path}")
    return download_url, file_path

def tg_download_file(download_url):
    debug_print(f"[TG] download file url={download_url}")
    body, code, headers = http_get(download_url, timeout=90)
    if code != 200:
        raise RuntimeError(f"download failed: {code}")
    content_type = headers.get("Content-Type")
    debug_print(f"[TG] download ok bytes={len(body)} content_type={content_type}")
    return body, content_type

# -------- Helpers: Group Message Detection --------
def is_group_chat(chat):
    """Check if the chat is a group or supergroup"""
    chat_type = chat.get("type", "")
    return chat_type in ("group", "supergroup")

def is_bot_mentioned(message, bot_username):
    """
    Check if the bot is mentioned in the message using @username.
    Returns (is_mentioned, cleaned_text) tuple.
    
    With Group Privacy ON, Telegram only forwards messages to the bot if:
    1. It's a /command
    2. The bot is @mentioned
    3. It's a reply to the bot's message
    
    This function detects @mentions and strips them from the text.
    """
    if not bot_username:
        debug_print("[GROUP] Warning: TELEGRAM_BOT_USERNAME not set, cannot detect @mentions")
        return False, message.get("text", "")
    
    text = message.get("text", "") or message.get("caption", "") or ""
    entities = message.get("entities", []) or message.get("caption_entities", [])
    
    debug_print(f"[GROUP] Checking for @mention of @{bot_username}")
    debug_print(f"[GROUP] Text: '{text}'")
    debug_print(f"[GROUP] Entities: {entities}")
    
    # Check for mention entities
    is_mentioned = False
    mention_positions = []  # Track positions to remove from text
    
    for entity in entities:
        if entity.get("type") == "mention":
            # Extract the mentioned username from text
            offset = entity.get("offset", 0)
            length = entity.get("length", 0)
            mentioned = text[offset:offset + length]
            debug_print(f"[GROUP] Found mention entity: '{mentioned}'")
            
            # Check if it's our bot (case-insensitive)
            if mentioned.lower() == f"@{bot_username.lower()}":
                is_mentioned = True
                mention_positions.append((offset, length))
                debug_print(f"[GROUP] ✓ Bot @mention detected!")
        
        elif entity.get("type") == "bot_command":
            # Commands like /start@botname also work
            offset = entity.get("offset", 0)
            length = entity.get("length", 0)
            command = text[offset:offset + length]
            if f"@{bot_username.lower()}" in command.lower():
                is_mentioned = True
                debug_print(f"[GROUP] ✓ Bot command with @mention detected: {command}")
    
    # Clean the text by removing bot mentions
    cleaned_text = text
    # Sort positions in reverse order to avoid offset issues when removing
    for offset, length in sorted(mention_positions, reverse=True):
        cleaned_text = cleaned_text[:offset] + cleaned_text[offset + length:]
    
    # Clean up extra whitespace
    cleaned_text = " ".join(cleaned_text.split()).strip()
    
    debug_print(f"[GROUP] is_mentioned={is_mentioned}, cleaned_text='{cleaned_text}'")
    return is_mentioned, cleaned_text

def is_reply_to_bot(message, bot_username):
    """Check if this message is a reply to a bot's message"""
    reply_to = message.get("reply_to_message")
    if not reply_to:
        return False
    
    reply_from = reply_to.get("from", {})
    # Check if the replied-to message was from the bot
    reply_username = reply_from.get("username", "")
    is_reply = reply_username.lower() == bot_username.lower() if bot_username else False
    
    debug_print(f"[GROUP] Reply to message from: @{reply_username}, is_reply_to_bot={is_reply}")
    return is_reply

def should_respond_in_group(message, chat, bot_username):
    """
    Determine if the bot should respond to this group message.
    
    With Group Privacy ON, Telegram already filters messages, but we still receive:
    1. /commands (with or without @botname)
    2. @botname mentions
    3. Replies to bot's messages
    
    Returns (should_respond, cleaned_text) tuple.
    """
    if not is_group_chat(chat):
        # Not a group chat, always respond
        return True, message.get("text", "") or message.get("caption", "")
    
    text = message.get("text", "") or message.get("caption", "") or ""
    
    debug_print(f"[GROUP] Evaluating group message: '{text[:100]}...' " if len(text) > 100 else f"[GROUP] Evaluating group message: '{text}'")
    
    # Check 1: Is it a /command?
    if text.startswith("/"):
        debug_print("[GROUP] ✓ Message is a command")
        return True, text
    
    # Check 2: Is the bot @mentioned?
    is_mentioned, cleaned_text = is_bot_mentioned(message, bot_username)
    if is_mentioned:
        debug_print("[GROUP] ✓ Bot is @mentioned")
        return True, cleaned_text
    
    # Check 3: Is it a reply to the bot?
    if is_reply_to_bot(message, bot_username):
        debug_print("[GROUP] ✓ Message is a reply to bot")
        return True, text
    
    # If we got here but received the message anyway, Telegram must have 
    # determined we should see it (privacy mode behavior)
    # This can happen with photos that have @mention in caption
    debug_print("[GROUP] Message received but no explicit trigger found - checking caption entities")
    
    # For photos/documents, check caption entities
    caption_entities = message.get("caption_entities", [])
    caption = message.get("caption", "")
    if caption_entities and caption:
        for entity in caption_entities:
            if entity.get("type") == "mention":
                offset = entity.get("offset", 0)
                length = entity.get("length", 0)
                mentioned = caption[offset:offset + length]
                if mentioned.lower() == f"@{bot_username.lower()}":
                    # Remove mention from caption
                    cleaned_caption = caption[:offset] + caption[offset + length:]
                    cleaned_caption = " ".join(cleaned_caption.split()).strip()
                    debug_print(f"[GROUP] ✓ Bot @mentioned in caption")
                    return True, cleaned_caption
    
    debug_print("[GROUP] ✗ No trigger found for group response")
    return False, text

# -------- Helpers: Direct Line --------
def dl_get_token_and_conversation_via_secret():
    """Generate a brand-new Direct Line token + conversation (cold start)."""
    url = f"{DIRECTLINE_BASE_URL}/v3/directline/tokens/generate"
    headers = {"Authorization": f"Bearer {DIRECTLINE_SECRET}"}
    debug_print(f"[DL] token generate via secret base={DIRECTLINE_BASE_URL}")
    body, code, _ = http_post_json(url, {}, headers=headers)
    if code not in (200, 201):
        raise RuntimeError(f"DL token generate failed: {code} {body}")
    obj = json.loads(body.decode())
    token  = obj.get("token")
    conv_id = obj.get("conversationId")
    debug_print(f"[DL] token generate ok conv_id={conv_id} token={'present' if token else 'missing'}")
    if not token:
        raise RuntimeError("No token returned from Direct Line")
    return token, conv_id


def dl_refresh_token(old_token):
    """Refresh an existing Direct Line token before it expires."""
    url = f"{DIRECTLINE_BASE_URL}/v3/directline/tokens/refresh"
    headers = {"Authorization": f"Bearer {old_token}"}
    debug_print("[DL] refreshing token")
    try:
        body, code, _ = http_post_json(url, {}, headers=headers)
        if code in (200, 201):
            obj = json.loads(body.decode())
            new_token = obj.get("token")
            debug_print(f"[DL] token refresh ok new_token={'present' if new_token else 'missing'}")
            return new_token
        debug_print(f"[DL] token refresh failed status={code}")
    except Exception as ex:
        debug_print(f"[DL] token refresh error: {ex}")
    return None


def dl_get_or_resume_conversation(session_key):
    """
    Try to resume an existing Direct Line conversation for this session_key.
    Falls back to creating a new one if no session exists or it's expired.
    Returns (token, conversation_id, watermark, is_new_conversation).
    """
    session = session_load(session_key)

    if session:
        token = session["token"]
        conv_id = session["conversation_id"]
        watermark = session.get("watermark", "")
        token_expires = float(session.get("token_expires_at", 0))

        # Refresh the token if it's about to expire (within 5 min)
        if time.time() > token_expires - 300:
            debug_print(f"[DL] Token nearing expiry, refreshing...")
            new_token = dl_refresh_token(token)
            if new_token:
                token = new_token
            else:
                # Token refresh failed – start fresh
                debug_print("[DL] Token refresh failed, starting new conversation")
                token, conv_id = dl_get_token_and_conversation_via_secret()
                return token, conv_id, None, True

        # Reconnect to existing conversation (this validates it's still alive)
        try:
            headers = {"Authorization": f"Bearer {token}"}
            reconnect_url = f"{DIRECTLINE_BASE_URL}/v3/directline/conversations/{conv_id}"
            body, code, _ = http_get_json(reconnect_url, headers=headers, timeout=15)
            if code == 200:
                debug_print(f"[DL] Resumed conversation conv_id={conv_id}")
                return token, conv_id, watermark, False
            else:
                debug_print(f"[DL] Reconnect failed status={code}, starting fresh")
        except Exception as ex:
            debug_print(f"[DL] Reconnect error: {ex}, starting fresh")

    # No valid session – create new
    token, _ = dl_get_token_and_conversation_via_secret()
    # Actually start the conversation (token/generate only gives a token, doesn't open it)
    headers = {"Authorization": f"Bearer {token}"}
    debug_print("[DL] Starting new conversation via POST /conversations")
    b_start, c_start, _ = http_post_json(
        f"{DIRECTLINE_BASE_URL}/v3/directline/conversations", {}, headers
    )
    if c_start not in (200, 201):
        raise RuntimeError(f"Start conversation failed: {c_start} {b_start}")
    conv_id = json.loads(b_start.decode())["conversationId"]
    debug_print(f"[DL] New conversation started conv_id={conv_id}")
    return token, conv_id, None, True

def dl_post_text(token, conversation_id, text, user_id):
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{DIRECTLINE_BASE_URL}/v3/directline/conversations/{conversation_id}/activities"
    
    client_activity_id = uuid.uuid4().hex[:10]
    now = datetime.now(timezone.utc)
    # Match Demo Website timestamp format with local timezone offset
    local_timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}+00:00"
    
    payload = {
        "attachments": [],
        "channelData": {
            "attachmentSizes": [],
            "cci_trace_id": uuid.uuid4().hex[:5],
            "clientActivityID": client_activity_id
        },
        "text": text,
        "textFormat": "plain",
        "type": "message",
        "cci_bot_id": os.environ.get("CCI_BOT_ID", ""),
        "cci_tenant_id": os.environ.get("CCI_TENANT_ID", ""),
        "cci_environment_id": os.environ.get("CCI_ENVIRONMENT_ID", ""),
        "channelId": "webchat",
        "from": {
            "id": user_id,
            "name": "",
            "role": "user"
        },
        "locale": "en-US",
        "localTimestamp": local_timestamp,
        "localTimezone": "Europe/Istanbul"
    }
    
    debug_print(f"[DL] post text conv={conversation_id} text_len={len(text)}")
    debug_print(f"[DL] post text CONTENT: '{text}'")
    debug_print(f"[DL] post text PAYLOAD: {json.dumps(payload, ensure_ascii=False)[:500]}")
    
    body, code, _ = http_post_json(url, payload, headers)
    if code not in (200, 201):
        debug_print(f"[DL][ERR] post text failed status={code} body={body}")
        raise RuntimeError(f"Post activity failed: {code} {body}")
    debug_print("[DL] post text ok")
    return conversation_id

def dl_upload_image(token, conversation_id, filename, content_type, content_bytes, user_id, text):
    """
    Image upload in Copilot Studio format
    We have thumbnailUrl, channelData and other metadata in activity.
    """
    headers = {"Authorization": f"Bearer {token}"}
    conv_id = conversation_id
    debug_print(f"[DL] uploading image to existing conversation conv_id={conv_id}")
    
    # 2) Cleanup Text
    if not text or text.strip() == "":
        text = DEFAULT_PROMPT
    text = text.strip()
    if text.startswith('"') and text.endswith('"'):
        text = text[1:-1]
    if text.startswith("'") and text.endswith("'"):
        text = text[1:-1]
    
    debug_print(f"[DL] Text: {text}")
    debug_print(f"[DL] Image: filename={filename}, content_type={content_type}, size={len(content_bytes)} bytes")
    
    # 3) Control Content-Type
    if not content_type or content_type == "application/octet-stream":
        guessed = mimetypes.guess_type(filename)[0]
        content_type = guessed or "image/jpeg"
        debug_print(f"[DL] Adjusted content_type to: {content_type}")
    
    # 4) Create Thumbnail (base64)
    thumbnail_b64 = base64.b64encode(content_bytes).decode('ascii')
    thumbnail_url = f"data:{content_type};base64,{thumbnail_b64}"
    
    # 5) Timestamps
    now = datetime.now(timezone.utc)
    local_timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}+00:00"
    
    # 6) Activity JSON - Copilot Studio format
    client_activity_id = uuid.uuid4().hex[:12]
    
    activity = {
        "attachments": [
            {
                "contentType": content_type,
                "name": filename,
                "thumbnailUrl": thumbnail_url
            }
        ],
        "channelData": {
            "attachmentSizes": [len(content_bytes)],
            "clientActivityID": client_activity_id
        },
        "text": text,
        "textFormat": "plain",
        "type": "message",
        "channelId": "webchat",
        "from": {
            "id": user_id,
            "name": "",
            "role": "user"
        },
        "locale": "en-US",
        "localTimestamp": local_timestamp,
        "localTimezone": "UTC",
        "cci_bot_id": os.environ.get("CCI_BOT_ID", ""),
        "cci_tenant_id": os.environ.get("CCI_TENANT_ID", ""),
        "cci_environment_id": os.environ.get("CCI_ENVIRONMENT_ID", "")        
    }
    
    activity_json = json.dumps(activity, ensure_ascii=False)
    debug_print(f"[DL] Activity JSON (first 500 chars): {activity_json[:500]}...")

    # 7) Upload URL
    upload_url = f"{DIRECTLINE_BASE_URL}/v3/directline/conversations/{conv_id}/upload?userId={urllib.parse.quote(user_id)}"
    debug_print(f"[DL] upload URL: {upload_url}")
    
    # 8) Upload with Copilot format
    b_up, c_up, h_up = http_post_multipart_copilot(
        upload_url,
        activity_json,
        filename,
        content_bytes,
        content_type,
        headers=headers,
        timeout=90
    )

    if c_up in (200, 201):
        debug_print(f"[DL] upload SUCCESS! status={c_up}")
        
        # Verification
        time.sleep(0.5)
        b_act, c_act, _ = http_get_json(
            f"{DIRECTLINE_BASE_URL}/v3/directline/conversations/{conv_id}/activities",
            headers=headers, timeout=30
        )
        acts = json.loads(b_act.decode("utf-8"))
        
        debug_print(f"[DL] Total activities: {len(acts.get('activities', []))}")
        
        if acts.get("activities"):
            user_acts = [a for a in acts["activities"] if a.get("from", {}).get("id", "").startswith("tg-")]
            
            if user_acts:
                last_user = user_acts[-1]
                debug_print(f"[DL] === USER MESSAGE AS RECEIVED BY BOT ===")
                debug_print(f"[DL] text: '{last_user.get('text', '')}'")
                
                atts = last_user.get("attachments") or []
                debug_print(f"[DL] attachments count: {len(atts)}")
                
                if atts:
                    att = atts[0]
                    ct = att.get('contentType', '')
                    curl = att.get('contentUrl', '')
                    debug_print(f"[DL] ✓ attachment contentType: {ct}")
                    if curl.startswith('data:'):
                        debug_print(f"[DL] ✓ attachment contentUrl: data URL (length: {len(curl)})")
                    elif "bot-framework-default-placeholder" in curl:
                        debug_print(f"[DL] ⚠️ PROBLEM: Still getting placeholder URL!")
                    else:
                        debug_print(f"[DL] ✓ attachment contentUrl: {curl[:100]}...")
        
        return conv_id
    
    debug_print(f"[DL][ERR] upload failed status={c_up} body={b_up}")
    raise RuntimeError(f"Upload failed: {c_up} {b_up}")


def extract_error_message_from_activity(activity):
    """
    Extract comprehensive error message from Copilot Studio activity.
    
    Copilot Studio sends error details in various places:
    - channelData.pva:error (for ContentFiltered and other errors)
    - channelData.error
    - value (for event activities)
    - entities with error type
    - OR as plain text in the message body (most common case!)
    
    Returns a tuple: (error_code, error_message) or (None, None) if no error
    """
    channel_data = activity.get("channelData", {})
    
    # Check for PVA (Power Virtual Agents / Copilot Studio) specific errors
    pva_data = channel_data.get("pva", {})
    if pva_data:
        error_info = pva_data.get("error", {})
        if error_info:
            error_code = error_info.get("code", "")
            error_message = error_info.get("message", "")
            debug_print(f"[DL] Found PVA error: code={error_code}, message={error_message}")
            return error_code, error_message
    
    # Check for direct error in channelData
    if "error" in channel_data:
        error_info = channel_data["error"]
        if isinstance(error_info, dict):
            error_code = error_info.get("code", "")
            error_message = error_info.get("message", "")
            return error_code, error_message
        elif isinstance(error_info, str):
            return None, error_info
    
    # Check for ContentFiltered specifically in various locations
    # Sometimes it's in the activity value for event type activities
    if activity.get("type") == "event":
        value = activity.get("value", {})
        if isinstance(value, dict):
            if "error" in value:
                error_info = value["error"]
                if isinstance(error_info, dict):
                    return error_info.get("code"), error_info.get("message")
    
    # Check entities for error information
    entities = activity.get("entities", [])
    for entity in entities:
        if entity.get("type") == "error" or "error" in entity:
            error_data = entity.get("error", entity)
            if isinstance(error_data, dict):
                return error_data.get("code"), error_data.get("message")
    
    # Check for error in suggestedActions (sometimes errors come with suggestions)
    suggested_actions = activity.get("suggestedActions", {})
    if suggested_actions:
        actions = suggested_actions.get("actions", [])
        for action in actions:
            if "error" in str(action).lower():
                debug_print(f"[DL] Found error indication in suggestedActions: {action}")
    
    return None, None


def parse_error_from_text(text):
    """
    Parse error information from the message text itself.
    
    Copilot Studio often sends errors as plain text in this format:
    "Bir hata gerçekleşti.
    Hata kodu: ContentFiltered
    Conversation Id: xxx
    Zaman (UTC): xxx"
    
    Returns a dict with parsed error info, or None if not an error message.
    """
    if not text:
        return None
    
    # Check if this looks like an error message
    error_indicators = [
        "hata gerçekleşti",
        "hata kodu:",
        "error occurred",
        "error code:",
        "ContentFiltered",
        "RateLimited",
        "ServiceUnavailable"
    ]
    
    text_lower = text.lower()
    is_error = any(indicator.lower() in text_lower for indicator in error_indicators)
    
    if not is_error:
        return None
    
    debug_print(f"[PARSE] Detected error message in text, parsing...")
    
    result = {
        "error_code": None,
        "conversation_id": None,
        "timestamp": None
    }
    
    # Parse each line
    lines = text.strip().split('\n')
    for line in lines:
        line = line.strip()
        line_lower = line.lower()
        
        # Parse error code
        if "hata kodu:" in line_lower or "error code:" in line_lower:
            parts = line.split(':', 1)
            if len(parts) > 1:
                result["error_code"] = parts[1].strip()
                debug_print(f"[PARSE] Found error_code: {result['error_code']}")
        
        # Parse conversation ID
        elif "conversation id:" in line_lower:
            parts = line.split(':', 1)
            if len(parts) > 1:
                result["conversation_id"] = parts[1].strip()
                debug_print(f"[PARSE] Found conversation_id: {result['conversation_id']}")
        
        # Parse timestamp
        elif "zaman (utc):" in line_lower or "time (utc):" in line_lower:
            parts = line.split(':', 1)
            if len(parts) > 1:
                result["timestamp"] = parts[1].strip()
                debug_print(f"[PARSE] Found timestamp: {result['timestamp']}")
    
    return result if result["error_code"] else None


def format_error_for_telegram(error_code, error_message, conversation_id, timestamp=None):
    """
    Format a comprehensive error message for Telegram users,
    similar to what Copilot Studio shows in its test interface.
    """
    if not timestamp:
        now = datetime.now(timezone.utc)
        timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}Z"
    
    # Map error codes to user-friendly Turkish messages (matching Copilot Studio's messages)
    error_descriptions = {
        "ContentFiltered": "İçerik, Sorumlu Yapay Zeka kısıtlamaları nedeniyle engellendi.",
        "RateLimited": "Çok fazla istek gönderildi. Lütfen biraz bekleyip tekrar deneyin.",
        "ServiceUnavailable": "Servis geçici olarak kullanılamıyor.",
        "Timeout": "İstek zaman aşımına uğradı.",
        "InvalidRequest": "Geçersiz istek.",
        "InternalServerError": "Dahili sunucu hatası oluştu.",
        "BadGateway": "Ağ geçidi hatası.",
        "GatewayTimeout": "Ağ geçidi zaman aşımı.",
        "TooManyRequests": "Çok fazla istek gönderildi. Lütfen bekleyin.",
        "Unauthorized": "Yetkilendirme hatası.",
        "Forbidden": "Erişim reddedildi.",
    }
    
    # Get description for the error code, or use the original message
    description = error_descriptions.get(error_code, error_message) if error_code else error_message
    
    # Build comprehensive error message
    parts = []
    
    if description:
        parts.append(f"**Hata Mesajı:** {description}")
    
    if error_code:
        parts.append(f"**Hata Kodu:** {error_code}")
    
    parts.append(f"**Conversation Id:** {conversation_id}")
    parts.append(f"**Zaman (UTC):** {timestamp}")
    
    return "\n".join(parts)


def enrich_error_text(original_text, conversation_id):
    """
    Take the original error text from Copilot and enrich it with
    the detailed error message description.
    
    Input text format:
    "Bir hata gerçekleşti.
    Hata kodu: ContentFiltered
    Conversation Id: xxx
    Zaman (UTC): xxx"
    
    Output adds the detailed description like Copilot Studio test interface.
    """
    parsed = parse_error_from_text(original_text)
    
    if not parsed:
        return None  # Not an error message
    
    error_code = parsed.get("error_code")
    conv_id = parsed.get("conversation_id") or conversation_id
    timestamp = parsed.get("timestamp")
    
    # Format with the enriched description
    return format_error_for_telegram(error_code, None, conv_id, timestamp)


def dl_poll_reply_text_and_attachments(token, conversation_id,
                                       max_wait_seconds=None,
                                       initial_interval=None,
                                       backoff_factor=None,
                                       max_interval=None,
                                       user_id_prefix="tg-",
                                       start_watermark=None,
                                       tg_chat_id=None):
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{DIRECTLINE_BASE_URL}/v3/directline/conversations/{conversation_id}/activities"

    max_wait_seconds = float(max_wait_seconds or DL_MAX_WAIT_SECONDS)
    interval = float(initial_interval or DL_INITIAL_POLL_INTERVAL)
    factor = float(backoff_factor or DL_BACKOFF_FACTOR)
    max_interval = float(max_interval or DL_MAX_POLL_INTERVAL)

    deadline = time.time() + max_wait_seconds
    watermark = start_watermark
    replies = []
    attempt = 0
    last_typing_time = 0  # Send typing action immediately on first iteration

    debug_print(f"[DL] poll replies (adaptive) conv={conversation_id} "
          f"max_wait={max_wait_seconds}s start_interval={interval}s backoff={factor} max_interval={max_interval}s")

    while time.time() < deadline:
        attempt += 1

        # Send "typing" indicator every ~4 seconds (Telegram clears it after ~5s)
        if tg_chat_id and time.time() - last_typing_time >= 4:
            tg_send_chat_action(tg_chat_id, "typing")
            last_typing_time = time.time()

        q = f"?watermark={urllib.parse.quote(watermark)}" if watermark else ""
        body, code, _ = http_get(url + q, headers, timeout=90)
        if code != 200:
            debug_print(f"[DL] poll http status={code} (attempt={attempt}) -> stop polling")
            break

        obj = json.loads(body.decode())
        watermark = obj.get("watermark")
        activities = obj.get("activities", [])
        debug_print(f"[DL] poll got activities={len(activities)} watermark={watermark} attempt={attempt}")

        for act in activities:
            # Log the full activity for debugging
            debug_print(f"[DL] Activity: type={act.get('type')} from={act.get('from', {}).get('id', 'unknown')}")
            debug_print(f"[DL] Activity channelData: {json.dumps(act.get('channelData', {}), ensure_ascii=False)[:500]}")
            
            # Check if this is a bot message (not from user)
            from_id = act.get("from", {}).get("id", "")
            is_from_user = from_id.startswith(user_id_prefix)
            
            if act.get("type") == "message" and not is_from_user:
                text = act.get("text")
                atts = act.get("attachments") or []
                
                # Extract error information
                error_code, error_message = extract_error_message_from_activity(act)
                
                debug_print(f"[DL] bot message text_len={len(text or '')} attachments={len(atts)} error_code={error_code}")
                
                reply_data = {
                    "text": text, 
                    "attachments": atts,
                    "error_code": error_code,
                    "error_message": error_message,
                    "conversation_id": conversation_id,
                    "channel_data": act.get("channelData", {})  # Include full channelData for debugging
                }
                replies.append(reply_data)
            
            # Also check for event activities that might contain errors
            elif act.get("type") == "event" and not is_from_user:
                error_code, error_message = extract_error_message_from_activity(act)
                if error_code or error_message:
                    debug_print(f"[DL] Found error in event activity: code={error_code}, message={error_message}")
                    reply_data = {
                        "text": None,
                        "attachments": [],
                        "error_code": error_code,
                        "error_message": error_message,
                        "conversation_id": conversation_id,
                        "channel_data": act.get("channelData", {})
                    }
                    replies.append(reply_data)

        if replies:
            debug_print(f"[DL] poll done replies={len(replies)} in_attempts={attempt}")
            return replies, watermark

        jitter = random.uniform(-0.1, 0.1)
        sleep_for = max(0.1, min(max_interval, interval + jitter))
        now_left = max(0, deadline - time.time())
        sleep_for = min(sleep_for, now_left)
        debug_print(f"[DL] no reply yet; sleeping {sleep_for:.2f}s (attempt={attempt})")
        time.sleep(sleep_for)

        interval = min(max_interval, interval * factor)

    debug_print("[DL] poll timeout/no replies (adaptive)")
    return replies, watermark

def dl_send_conversation_update(token, conversation_id, user_id):
    """Send conversationUpdate to trigger Copilot Studio's greeting/init topics."""
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{DIRECTLINE_BASE_URL}/v3/directline/conversations/{conversation_id}/activities"
    
    payload = {
        "type": "conversationUpdate",
        "membersAdded": [
            {"id": user_id, "name": "", "role": "user"}
        ],
        "from": {
            "id": user_id,
            "name": "",
            "role": "user"
        }
    }
    
    debug_print(f"[DL] sending conversationUpdate conv={conversation_id}")
    body, code, _ = http_post_json(url, payload, headers)
    debug_print(f"[DL] conversationUpdate status={code}")
    return code in (200, 201)

# -------- Security --------
def validate_telegram_secret(headers):
    if not REQUIRE_TG_SECRET:
        debug_print("[SEC] REQUIRE_TG_SECRET=false -> skipping secret header validation")
        return True
    sent = headers.get("x-telegram-bot-api-secret-token") or headers.get("X-Telegram-Bot-Api-Secret-Token")
    ok = (TELEGRAM_SECRET_TOKEN and sent == TELEGRAM_SECRET_TOKEN)
    debug_print(f"[SEC] secret header present={bool(sent)} match={ok}")
    return ok

# -------- Lambda Handler --------
def lambda_handler(event, context):
    t0 = time.time()
    debug_print(f"[INVOKE] time={datetime.utcnow().isoformat()}Z "
          f"func_url=True method={event.get('requestContext',{}).get('http',{}).get('method')} "
          f"path={event.get('rawPath')} isBase64={event.get('isBase64Encoded')}")
    headers = { (k.lower() if isinstance(k,str) else k): v for k,v in (event.get("headers") or {}).items() }
    if not validate_telegram_secret(headers):
        error_print("[INVOKE] unauthorized (secret mismatch)")
        return {"statusCode": 401, "body": "unauthorized"}

    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        import base64 as b64
        debug_print("[INVOKE] decoding base64 body")
        raw = b64.b64decode(raw).decode("utf-8")

    try:
        update = json.loads(raw)
        debug_print(f"[UPDATE] keys={list(update.keys())}")
    except Exception as ex:
        error_print(f"invalid json ex={ex}")
        return {"statusCode": 400, "body": "invalid json"}

    # ========== DEDUP: skip Telegram webhook retries ==========
    update_id = update.get("update_id")
    if update_id and not dedup_check_and_lock(update_id):
        debug_print(f"[INVOKE] duplicate update_id={update_id} -> returning 200")
        return {"statusCode": 200, "body": "duplicate"}

    message = (update.get("message") or update.get("edited_message")) or {}
    
    debug_print(f"Complete message structure:")
    debug_print(f"message = {json.dumps(message, ensure_ascii=False, indent=2)}")
    
    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    chat_type = chat.get("type", "private")
    message_id = message.get("message_id")  # For reply functionality
    uid = str(message.get('from', {}).get('id', ''))
    user_id = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"telegram-{uid}"))
    
    # Session key: in groups, each user gets their own session (chat_id:uid)
    # In private chats, chat_id alone is sufficient (it's unique per user)
    if chat_type in ("group", "supergroup"):
        session_key = f"{chat_id}:{uid}"
    else:
        session_key = str(chat_id)

    debug_print(f"[CTX] chat_id={chat_id} chat_type={chat_type} message_id={message_id} user_id={user_id} session_key={session_key}")

    if not chat_id:
        debug_print("[INVOKE] no chat -> 200")
        return {"statusCode": 200, "body": "no chat"}
    
    # ========== GROUP MESSAGE HANDLING ==========
    # Check if we should respond to this message (for groups)
    should_respond, cleaned_text = should_respond_in_group(message, chat, TELEGRAM_BOT_USERNAME)
    
    if not should_respond:
        debug_print(f"[GROUP] Skipping message - bot not addressed in group")
        return {"statusCode": 200, "body": "not addressed"}
    
    # Use cleaned text (with @mention removed) for further processing
    original_text = message.get("text")
    if cleaned_text != original_text and cleaned_text:
        debug_print(f"[GROUP] Using cleaned text: '{cleaned_text}' (original: '{original_text}')")
        message["text"] = cleaned_text
    
    # For group chats, we'll reply to the original message for context
    reply_to_id = message_id if is_group_chat(chat) else None
    
    # Check messages with images for /bot or /yeni commands in caption
    caption = message.get('caption', '')

    # /bot with following query with image
    if caption and caption.startswith('/bot'):
        session_delete(session_key)
        cleaned_caption = caption.removeprefix('/bot')
        if not cleaned_caption:
            cleaned_caption = DEFAULT_PROMPT
        debug_print(f"[GROUP] Using cleaned caption: '{cleaned_caption}' (original: '{caption}')")
        message["caption"] = cleaned_caption
        message["text"] = cleaned_caption  

    # /yeni with following query with image
    if caption and caption.startswith('/yeni'):
        session_delete(session_key)
        cleaned_caption = caption.removeprefix('/yeni')
        if not cleaned_caption:
            cleaned_caption = DEFAULT_PROMPT
        debug_print(f"[GROUP] Using cleaned caption: '{cleaned_caption}' (original: '{caption}')")
        message["caption"] = cleaned_caption
        message["text"] = cleaned_caption


    text = message.get('text', '')

    # Handle /bot command without image
    if text and text in ('/bot', f'/bot@{TELEGRAM_BOT_USERNAME}'):
        # Clear existing session so the user starts fresh
        session_delete(session_key)
        user_name = message.get('from', {}).get('first_name', '')
        welcome_text = (
            f"Merhaba {user_name}! 👋. Aramıza Hoş Geldin! ✨\n\n"
            "İPK Platformu üzerinden yürütülen yardımseverlik koşularına ve elbette yüzme yarışlarına dair sorularına Yapay Zeka desteğiyle anında yanıt bulmak için bana ulaştığını varsayıyorum.\n"
            "Dayanışma ekosistemimizin verimliliğini sürekli kılmak üzere lütfen aşağıdaki kuralları dikkate alalım:\n"
            "👉 **Sorular / Yanıtlar:** Burada bir dijital asistan 🤖 ile yazışıyorsun. Sorularını net ve yardımseverlik koşusu odaklı sorman, en doğru yanıtı almanı sağlar.⚠️\n"
            "👉 Sorunu yöneltirken bana metin 📝 mesajı veya resim 🖼 gönderebilirsin. Eğer görme engelliysen ve yanıtımı betimleme yaparak yazmamı tercih edersen, bunu önceden belirtmen yeterli.\n"
            "👉 **Sorumluluk sahibi olmak önemli:** Yaptığınız iş kolaylaşsın diye buradayım. Spesifik bir parkurda seninle yürümek hoşuma gider. Bana herhangi bir yapay zeka aracı gibi davranmaz, içini döküp, rahatlamak için fıkra filan istemezsen sevinirim. Yoğun kampanya dönemlerinde herkesin mutlaka bir sorusu olacaktır; kimseyi kuyrukta bekletmeyelim.\n"
            "👉 **Teyit şart 🔍:** Yanıtlar bazen hatalı bilgi içerebilir; elimdeki dokümanları tarayarak bir şeyler yazıyorum ve bazen benim de kafam karışabiliyor. Kritik kararlardan önce bilgileri teyit etmeyi unutma.\n"
            "👉 **Teknik Destek:** Sana yanıt veremediğim veya sistemsel bir sorun yaşadığın durumlarda mailini bekliyoruz: 📩 iyilikpesindekos@adimadim.org\n\n"
            "_Unutma, her bir gereksiz sorgu, gerçekten yardıma ihtiyaç duyan bir başka STK’nın yanıta ulaşmasını geciktirebilir. Hassasiyetin için şimdiden teşekkürler._\n\n"
            "**Evet, artık sorunu duyabilirim.**"
        )
        tg_send_message(chat_id, welcome_text, reply_to_message_id=reply_to_id)
            
        return {
            'statusCode': 200,
            'body': json.dumps({'status': 'ok'})
        }

    # /bot with following query without image
    if text and text.startswith('/bot'):
        session_delete(session_key)
        cleaned_text = text.removeprefix('/bot')
        debug_print(f"[GROUP] Using cleaned text: '{cleaned_text}' (original: '{text}')")
        message["text"] = cleaned_text

    # Handle /yeni command without image
    if text and text in ('/yeni', f'/yeni@{TELEGRAM_BOT_USERNAME}'):
        # Clear existing session so the user starts fresh
        session_delete(session_key)
        user_name = message.get('from', {}).get('first_name', '')
        new_text = (
            f"Pekala {user_name} ...\n\n**Yeni sorunu alabilirim.**"
        )
        tg_send_message(chat_id, new_text, reply_to_message_id=reply_to_id)
            
        return {
            'statusCode': 200,
            'body': json.dumps({'status': 'ok'})
        }

    # /yeni with following query without image
    if text and text.startswith('/yeni'):
        session_delete(session_key)
        cleaned_text = text.removeprefix('/yeni')
        debug_print(f"[GROUP] Using cleaned text: '{cleaned_text}' (original: '{text}')")
        message["text"] = cleaned_text    


    caption = message.get("caption")
    text = message.get("text")
    first_name = message.get('from', {}).get('first_name', 'İsimsiz')
    last_name = message.get('from', {}).get('last_name', '')
    full_name = f"{first_name} {last_name}".strip()

    # Check for supported content types
    photo_sizes = message.get("photo") or []
    doc = message.get("document")
    is_image_doc = doc and isinstance(doc, dict) and str(doc.get("mime_type","")).startswith("image/")
    has_image = bool(photo_sizes) or is_image_doc
    has_text = bool(text)

    # Check for unsupported content types
    unsupported_content = (
        message.get("video") or
        message.get("audio") or
        message.get("voice") or
        message.get("video_note") or
        message.get("sticker") or
        message.get("animation") or
        message.get("location") or
        message.get("venue") or
        message.get("contact") or
        message.get("poll") or
        message.get("dice") or
        message.get("game") or
        (doc and not is_image_doc)  # Non-image documents
    )

    if unsupported_content:
        debug_print(f"[FLOW] Unsupported content type detected")
        tg_send_message(chat_id, 
            f"Yalnızca metin ya da resim kabul edebiliyorum.\n\n"
            "Size nasıl yardımcı olabilirim?",
            reply_to_message_id=reply_to_id
        )

        return {"statusCode": 200, "body": "unsupported content type"}

    if not caption and not text:
        caption = DEFAULT_PROMPT
        debug_print(f"[FLOW] no caption/text -> using default prompt text_len={len(caption)}")
    else:
        if caption:
            debug_print(f"[FLOW] caption detected text_len={len(caption)}")
        if text:
            debug_print(f"[FLOW] text detected len={len(text)}")

    try:
        token, conv_id, watermark, is_new = dl_get_or_resume_conversation(session_key)
        debug_print(f"[FLOW] conversation: conv_id={conv_id} is_new={is_new} watermark={watermark}")

        if is_new:
            debug_print(f"[FLOW] new conversation, skipping conversationUpdate")

        message_to_send = text or caption

        info_print(f"[TG] User <{full_name}> said: <{message_to_send}>")

        # If no image, send text only
        if not has_image:
            if message_to_send:
                debug_print(f"[FLOW] No image, sending text only: len={len(message_to_send)}")
                conv_id = dl_post_text(token, conv_id, message_to_send, user_id)
        
        # If image present, send in Copilot format
        sent_image = False

        if photo_sizes:
            file_id = photo_sizes[-1]["file_id"]
            debug_print(f"[FLOW] photo detected file_id={file_id}")
            download_url, file_path = tg_get_file(file_id)
            img_bytes, content_type = tg_download_file(download_url)
            if not content_type:
                content_type = mimetypes.guess_type(file_path)[0] or "image/jpeg"
            filename = os.path.basename(file_path) or f"photo_{int(time.time())}.jpg"
            
            instruction = caption or DEFAULT_PROMPT
            debug_print(f"[FLOW] Sending image WITH instruction: '{instruction}'")
            conv_id = dl_upload_image(token, conv_id, filename, content_type, img_bytes, user_id, instruction)
            sent_image = True

        elif doc and isinstance(doc, dict) and str(doc.get("mime_type","")).startswith("image/"):
            mime = doc.get("mime_type", "")
            debug_print(f"[FLOW] document detected mime={mime}")
            file_id = doc["file_id"]
            download_url, file_path = tg_get_file(file_id)
            img_bytes, content_type = tg_download_file(download_url)
            if not content_type:
                content_type = mimetypes.guess_type(file_path)[0] or "image/jpeg"
            filename = os.path.basename(file_path) or f"image_{int(time.time())}"
            
            instruction = caption or DEFAULT_PROMPT
            debug_print(f"[FLOW] Sending document image WITH instruction: '{instruction}'")
            conv_id = dl_upload_image(token, conv_id, filename, content_type, img_bytes, user_id, instruction)
            sent_image = True

        # Poll for replies — use watermark from session to skip old messages
        replies, last_watermark = dl_poll_reply_text_and_attachments(
            token, conv_id,
            max_wait_seconds=DL_MAX_WAIT_SECONDS,
            start_watermark=watermark,
            user_id_prefix=user_id,
            tg_chat_id=chat_id
        )

        # Persist session so the next message continues this conversation
        session_save(session_key, token, conv_id, watermark=last_watermark)

        if not replies:
            error_print(f"Cannot find actual reply from Copilot backend")
            msg = "Arka uçtan yanıt alınamadı. Lütfen daha sonra tekrar deneyiniz." if not sent_image else \
                  "Görsel alındı, yanıt hazırlanıyor."
            tg_send_message(chat_id, msg, reply_to_message_id=reply_to_id)
            dt = time.time() - t0
            debug_print(f"[DONE] no replies total_ms={int(dt*1000)}")
            return {"statusCode": 200, "body": "ok"}

        for idx, r in enumerate(replies, 1):
            debug_print(f"[REPLY] #{idx} text_len={len(r.get('text') or '')} atts={len(r.get('attachments') or [])} error_code={r.get('error_code')}")
            
            reply_text = r.get("text")
            
            # Check for error in channelData first
            error_code = r.get("error_code")
            error_message = r.get("error_message")
            
            if error_code or error_message:
                # Format comprehensive error message like Copilot Studio does
                formatted_error = format_error_for_telegram(
                    error_code, 
                    error_message, 
                    r.get("conversation_id", conv_id)
                )
                tg_send_message(chat_id, formatted_error, reply_to_message_id=reply_to_id)
            elif reply_text:
                # Check if the text itself contains an error message
                enriched_error = enrich_error_text(reply_text, conv_id)
                
                if enriched_error:
                    # This was an error message - send the enriched version
                    debug_print(f"[REPLY] Detected error in text, sending enriched version")
                    tg_send_message(chat_id, enriched_error, reply_to_message_id=reply_to_id)
                else:
                    # Normal message - send as-is with disclaimer
                    disclaimer_suffix = f"\n\n_{AI_DISCLAIMER}_" if AI_DISCLAIMER else ""
                    tg_send_message(chat_id, reply_text + disclaimer_suffix, reply_to_message_id=reply_to_id)
            
            for a in (r.get("attachments") or []):
                curl = a.get("contentUrl")
                ctype = a.get("contentType", "")
                name = a.get("name") or ""
                debug_print(f"[REPLY-ATT] type={ctype} url_present={bool(curl)} name={name}")
                if curl and curl.startswith("http") and ctype.startswith("image/"):
                    tg_send_photo_by_url(chat_id, curl, caption=name, reply_to_message_id=reply_to_id)

    except Exception as ex:
        error_print(f"flow ex={ex}")
        tg_send_message(chat_id, f"Bir hata oluştu ({ex}). Lütfen tekrar deneyiniz.", reply_to_message_id=reply_to_id)

    dt = time.time() - t0
    debug_print(f"[DONE] total_ms={int(dt*1000)}")
    return {"statusCode": 200, "body": "ok"}