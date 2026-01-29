# lambda_function.py
import base64
import json
import mimetypes
import os
import time
import urllib.request
import urllib.parse
import urllib.error
import uuid
import random
from datetime import datetime, timezone
from wsgiref import headers

TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
REQUIRE_TG_SECRET  = os.environ.get("REQUIRE_TG_SECRET", "false").lower() == "true"
LOGGING = os.environ.get("LOGGING", "error").lower() # debug, info, error

TELEGRAM_SECRET_TOKEN = os.environ.get("TELEGRAM_SECRET_TOKEN", "")
DIRECTLINE_SECRET  = os.environ["DIRECTLINE_SECRET"]
DIRECTLINE_BASE_URL = os.environ.get("DIRECTLINE_BASE_URL", "https://directline.botframework.com")
DEFAULT_PROMPT = os.environ.get("DEFAULT_PROMPT", "Bu ekran görüntüsündeki problemi nasıl çözebilirim?")

# Bot username (without @) - needed for group mention detection
# Set this in Lambda environment variables, e.g., "AdimAdimSTKBot"
TELEGRAM_BOT_USERNAME = os.environ.get("TELEGRAM_BOT_USERNAME", "")

# ---- Tuning knobs for polling patience ----
DL_MAX_WAIT_SECONDS = float(os.environ.get("DL_MAX_WAIT_SECONDS", "30"))
DL_INITIAL_POLL_INTERVAL = float(os.environ.get("DL_INITIAL_POLL_INTERVAL", "0.6"))
DL_BACKOFF_FACTOR = float(os.environ.get("DL_BACKOFF_FACTOR", "1.5"))
DL_MAX_POLL_INTERVAL = float(os.environ.get("DL_MAX_POLL_INTERVAL", "3.0"))


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
def tg_send_message(chat_id, text, reply_to_message_id=None):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}
    if reply_to_message_id:
        payload["reply_to_message_id"] = reply_to_message_id
    debug_print(f"[TG] sendMessage chat_id={chat_id} text_len={len(text)} reply_to={reply_to_message_id}")
    _, code, _ = http_post_json(url, payload)
    debug_print(f"[TG] sendMessage status={code}")
    info_print(f"[TG] Message sent to user: <{text}>")
    return code == 200

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

def dl_post_text(token, conversation_id_unused, text, user_id):
    headers = {"Authorization": f"Bearer {token}"}

    debug_print("[DL] start conversation (always)")
    b_start, c_start, _ = http_post_json(f"{DIRECTLINE_BASE_URL}/v3/directline/conversations", {}, headers)
    if c_start not in (200, 201):
        debug_print(f"[DL][ERR] start conversation failed status={c_start} body={b_start}")
        raise RuntimeError(f"Start conversation failed: {c_start} {b_start}")
    conv_id = json.loads(b_start.decode())["conversationId"]
    debug_print(f"[DL] conversation started id={conv_id}")

    url = f"{DIRECTLINE_BASE_URL}/v3/directline/conversations/{conv_id}/activities"
    
    # Payload in Copilot Studio format
    client_activity_id = uuid.uuid4().hex[:12]
    now = datetime.now(timezone.utc)
    local_timestamp = now.strftime("%Y-%m-%dT%H:%M:%S.") + f"{now.microsecond // 1000:03d}+00:00"
    
    payload = {
        "type": "message",
        "text": text,
        "textFormat": "plain",
        "channelId": "webchat",
        "from": {
            "id": user_id,
            "name": "",
            "role": "user"
        },
        "locale": "tr-TR",
        "localTimestamp": local_timestamp,
        "localTimezone": "Europe/Istanbul",
        "channelData": {
            "clientActivityID": client_activity_id
        }
    }
    
    debug_print(f"[DL] post text conv={conv_id} url={repr(url)} text_len={len(text)}")
    debug_print(f"[DL] post text CONTENT: '{text}'")
    
    body, code, _ = http_post_json(url, payload, headers)
    if code not in (200, 201):
        debug_print(f"[DL][ERR] post text failed status={code} body={body}")
        raise RuntimeError(f"Post activity failed: {code} {body}")
    debug_print("[DL] post text ok")
    return conv_id

def dl_upload_image(token, conversation_id_unused, filename, content_type, content_bytes, user_id, text):
    """
    Image upload in Copilot Studio format
    We have thumbnailUrl, channelData and other metadata in activity.
    """
    headers = {"Authorization": f"Bearer {token}"}
    
    # 1) Open conversation
    debug_print("[DL] start conversation (always) for upload")
    b_start, c_start, _ = http_post_json(f"{DIRECTLINE_BASE_URL}/v3/directline/conversations", {}, headers)
    if c_start not in (200, 201):
        debug_print(f"[DL][ERR] start conversation failed status={c_start} body={b_start}")
        raise RuntimeError(f"Start conversation failed: {c_start} {b_start}")
    conv_id = json.loads(b_start.decode())["conversationId"]
    debug_print(f"[DL] conversation started id={conv_id}")
    
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
        "localTimezone": "UTC"
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

def dl_poll_reply_text_and_attachments(token, conversation_id,
                                       max_wait_seconds=None,
                                       initial_interval=None,
                                       backoff_factor=None,
                                       max_interval=None,
                                       user_id_prefix="tg-"):
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{DIRECTLINE_BASE_URL}/v3/directline/conversations/{conversation_id}/activities"

    max_wait_seconds = float(max_wait_seconds or DL_MAX_WAIT_SECONDS)
    interval = float(initial_interval or DL_INITIAL_POLL_INTERVAL)
    factor = float(backoff_factor or DL_BACKOFF_FACTOR)
    max_interval = float(max_interval or DL_MAX_POLL_INTERVAL)

    deadline = time.time() + max_wait_seconds
    watermark = None
    replies = []
    attempt = 0

    debug_print(f"[DL] poll replies (adaptive) conv={conversation_id} "
          f"max_wait={max_wait_seconds}s start_interval={interval}s backoff={factor} max_interval={max_interval}s")

    while time.time() < deadline:
        attempt += 1
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
            if act.get("type") == "message" and not act.get("from", {}).get("id", "").startswith(user_id_prefix):
                text = act.get("text")
                atts = act.get("attachments") or []
                debug_print(f"[DL] bot message text_len={len(text or '')} attachments={len(atts)}")
                replies.append({"text": text, "attachments": atts})

        if replies:
            debug_print(f"[DL] poll done replies={len(replies)} in_attempts={attempt}")
            return replies

        jitter = random.uniform(-0.1, 0.1)
        sleep_for = max(0.1, min(max_interval, interval + jitter))
        now_left = max(0, deadline - time.time())
        sleep_for = min(sleep_for, now_left)
        debug_print(f"[DL] no reply yet; sleeping {sleep_for:.2f}s (attempt={attempt})")
        time.sleep(sleep_for)

        interval = min(max_interval, interval * factor)

    debug_print("[DL] poll timeout/no replies (adaptive)")
    return replies

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

    message = (update.get("message") or update.get("edited_message")) or {}
    
    debug_print(f"Complete message structure:")
    debug_print(f"message = {json.dumps(message, ensure_ascii=False, indent=2)}")
    
    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    chat_type = chat.get("type", "private")
    message_id = message.get("message_id")  # For reply functionality
    user_id = f"tg-{chat_id}"
    
    debug_print(f"[CTX] chat_id={chat_id} chat_type={chat_type} message_id={message_id} user_id={user_id}")

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
    
    uid = str(message.get('from', {}).get('id', ''))
    
    # Handle /bot command
    text = message.get('text', '')
    if text and (text.startswith('/bot') or text.startswith(f'/bot@{TELEGRAM_BOT_USERNAME}')):
        user_name = message.get('from', {}).get('first_name', '')
        welcome_text = (
            f"Merhaba {user_name}! 👋\n\n"
            "Ben Adım Adım STK yardımcınızım. Bana metin mesajı veya resim gönderebilirsiniz.\n\n"
            "Size nasıl yardımcı olabilirim?"
        )
        tg_send_message(chat_id, welcome_text, reply_to_message_id=reply_to_id)
            
        return {
            'statusCode': 200,
            'body': json.dumps({'status': 'ok'})
        }    

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
        token, conv_id = dl_get_token_and_conversation_via_secret()

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

        replies = dl_poll_reply_text_and_attachments(token, conv_id, max_wait_seconds=DL_MAX_WAIT_SECONDS)
        if not replies:
            error_print(f"Cannot find actual reply from Copilot backend")
            msg = "Arka uçtan yanıt alınamadı. Lütfen daha sonra tekrar deneyiniz." if not sent_image else \
                  "Görsel alındı, yanıt hazırlanıyor."
            tg_send_message(chat_id, msg, reply_to_message_id=reply_to_id)
            dt = time.time() - t0
            debug_print(f"[DONE] no replies total_ms={int(dt*1000)}")
            return {"statusCode": 200, "body": "ok"}

        for idx, r in enumerate(replies, 1):
            debug_print(f"[REPLY] #{idx} text_len={len(r.get('text') or '')} atts={len(r.get('attachments') or [])}")
            if r.get("text"):
                tg_send_message(chat_id, r["text"], reply_to_message_id=reply_to_id)
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