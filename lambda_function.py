
# lambda_function.py  -- verbose logging (print) enabled
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
from datetime import datetime
from wsgiref import headers

TELEGRAM_BOT_TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
REQUIRE_TG_SECRET  = os.environ.get("REQUIRE_TG_SECRET", "false").lower() == "true"
TELEGRAM_SECRET_TOKEN = os.environ.get("TELEGRAM_SECRET_TOKEN", "")
DIRECTLINE_SECRET  = os.environ["DIRECTLINE_SECRET"]
DIRECTLINE_BASE_URL = os.environ.get("DIRECTLINE_BASE_URL", "https://directline.botframework.com")
DEFAULT_PROMPT = os.environ.get("DEFAULT_PROMPT", "Buradaki problemi nasıl çözebilirim?")

# ---- Tuning knobs for polling patience ----
DL_MAX_WAIT_SECONDS = float(os.environ.get("DL_MAX_WAIT_SECONDS", "30"))          # toplam bekleme penceresi
DL_INITIAL_POLL_INTERVAL = float(os.environ.get("DL_INITIAL_POLL_INTERVAL", "0.6"))  # ilk aralık (sn)
DL_BACKOFF_FACTOR = float(os.environ.get("DL_BACKOFF_FACTOR", "1.5"))            # çarpan
DL_MAX_POLL_INTERVAL = float(os.environ.get("DL_MAX_POLL_INTERVAL", "3.0"))      # en fazla aralık (sn)

# -------- Helpers: HTTP --------
def http_get(url, headers=None, timeout=15):
    print(f"[HTTP][GET] url={url} headers={_redact_headers(headers)} timeout={timeout}")
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        print(f"[HTTP][GET][{url}] status={resp.status} len={len(data)}")
        return data, resp.getcode(), dict(resp.headers)

def http_get_json(url, headers=None, timeout=90):
    """JSON beklenen GET: (body_bytes, status_code, headers_dict) döndürür.
       Accept: application/json ekler."""
    h = dict(headers or {})
    # Accept başlığı yoksa JSON iste
    if "Accept" not in {k.title(): v for k, v in h.items()}:
        h["Accept"] = "application/json"
    return http_get(url, headers=h, timeout=timeout)

def http_post_json(url, payload, headers=None, timeout=20):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    body = json.dumps(payload).encode("utf-8")
    print(f"[HTTP][POST-JSON] url={url} headers={_redact_headers(h)} bytes={len(body)}")
    req = urllib.request.Request(url, data=body, headers=h, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        data = resp.read()
        print(f"[HTTP][POST-JSON][{url}] status={resp.status} len={len(data)}")
        return data, resp.getcode(), dict(resp.headers)

def http_post_multipart(url, fields, files, headers=None, timeout=90):
    boundary = "----WebKitFormBoundary{}".format(uuid.uuid4().hex)
    print(f"[HTTP][POST-MP] url={url} boundary={boundary} fields={list(fields.keys()) if fields else []} "
          f"files={[f.get('filename') for f in (files or [])]}")
    body_parts = []

    def add_part(hdrs, content):
        body_parts.append(("--" + boundary).encode())
        for hk, hv in hdrs.items():
            body_parts.append(f"{hk}: {hv}".encode())
        body_parts.append(b"")
        body_parts.append(content if isinstance(content, (bytes, bytearray)) else content.encode("utf-8"))

    for f in (files or []):
        add_part({
            "Content-Disposition": f'form-data; name="{f["name"]}"; filename="{f["filename"]}"',
            "Content-Type": f.get("content_type") or "application/octet-stream",
        }, f["content"])

    for name, (content, ctype) in (fields or {}).items():
        if name == "activity":
            add_part({
                "Content-Disposition": f'form-data; name="{name}"',  
                "Content-Type": ctype or "application/vnd.microsoft.activity",
            }, content)
        else:
            # Diğer field'lar için önceki davranış korunabilir veya filename kaldırılabilir
            add_part({
                "Content-Disposition": f'form-data; name="{name}"',
                "Content-Type": ctype or "text/plain; charset=utf-8",
            }, content)

    body_parts.append(("--" + boundary + "--").encode())
    data = b"\r\n".join(body_parts)

    h = {"Content-Type": f"multipart/form-data; boundary={boundary}",
         "Content-Length": str(len(data))}
    if headers:
        h.update(headers)

    print(f"[HTTP][POST-MP] headers={_redact_headers(h)} total_bytes={len(data)}")

    try:
        req = urllib.request.Request(url, data=data, headers=h, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            rdata = resp.read()
            print(f"[HTTP][POST-MP][{url}] status={resp.status} len={len(rdata)}")
            return rdata, resp.getcode(), dict(resp.headers)
    except urllib.error.HTTPError as e:
        err_body = e.read()
        print(f"[HTTP][POST-MP][ERR] status={e.code} body={err_body}")
        # Aynı interface'i koruyalım:
        return err_body, e.code, dict(e.headers or {})


def _redact_headers(h):
    if not h: return {}
    # Authorization/Token gibi alanları logda maskele
    redacted = {}
    for k, v in h.items():
        if k.lower() == "authorization":
            redacted[k] = v[:15] + "...(redacted)"
        else:
            redacted[k] = v
    return redacted

# -------- Helpers: Telegram --------
def tg_send_message(chat_id, text):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    payload = {"chat_id": chat_id, "text": text}
    print(f"[TG] sendMessage chat_id={chat_id} text_len={len(text)}")
    _, code, _ = http_post_json(url, payload)
    print(f"[TG] sendMessage status={code}")
    return code == 200

def tg_send_photo_by_url(chat_id, url_or_fileid, caption=None):
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendPhoto"
    payload = {"chat_id": chat_id, "photo": url_or_fileid}
    if caption:
        payload["caption"] = caption
    print(f"[TG] sendPhoto chat_id={chat_id} source={'url/fileid'} caption_len={len(caption or '')}")
    _, code, _ = http_post_json(url, payload)
    print(f"[TG] sendPhoto status={code}")
    return code == 200

def tg_get_file(file_id):
    # getFile -> file_path; sonra /file/ URL’inden indir.  (≥1 saat geçerli, 20MB sınırı) [2](https://community.powerplatform.com/forums/thread/details/?threadid=4d0f9b82-80cf-ef11-b8e8-6045bdd9204f)[3](https://tecnobits.com/en/How-to-use-Microsoft-Copilot-on-Telegram/)
    url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/getFile?file_id={urllib.parse.quote(file_id)}"
    print(f"[TG] getFile file_id={file_id}")
    body, code, _ = http_get(url)
    if code != 200:
        raise RuntimeError(f"getFile failed: {code} {body}")
    obj = json.loads(body.decode())
    if not obj.get("ok"):
        raise RuntimeError(f"getFile not ok: {obj}")
    file_path = obj["result"]["file_path"]
    download_url = f"https://api.telegram.org/file/bot{TELEGRAM_BOT_TOKEN}/{file_path}"
    print(f"[TG] getFile ok file_path={file_path}")
    return download_url, file_path

def tg_download_file(download_url):
    print(f"[TG] download file url={download_url}")
    body, code, headers = http_get(download_url, timeout=60)
    if code != 200:
        raise RuntimeError(f"download failed: {code}")
    content_type = headers.get("Content-Type")
    print(f"[TG] download ok bytes={len(body)} content_type={content_type}")
    return body, content_type

# -------- Helpers: Direct Line --------
def dl_get_token_and_conversation_via_secret():
    # Secret -> token generate (Direct Line 3.0)  [4](https://hookdeck.com/webhooks/platforms/how-to-receive-and-replay-external-webhooks-in-aws-lambda-with-hookdeck)
    url = f"{DIRECTLINE_BASE_URL}/v3/directline/tokens/generate"
    headers = {"Authorization": f"Bearer {DIRECTLINE_SECRET}"}
    print(f"[DL] token generate via secret base={DIRECTLINE_BASE_URL}")
    body, code, _ = http_post_json(url, {}, headers=headers)
    if code not in (200, 201):
        raise RuntimeError(f"DL token generate failed: {code} {body}")
    obj = json.loads(body.decode())
    token  = obj.get("token")
    conv_id = obj.get("conversationId")
    print(f"[DL] token generate ok conv_id={conv_id} token={'present' if token else 'missing'}")
    if not token:
        raise RuntimeError("No token returned from Direct Line")
    return token, conv_id

def dl_start_conversation_if_needed(token, conversation_id):
    headers = {"Authorization": f"Bearer {token}"}
    if conversation_id:
        print(f"[DL] reuse existing conversation_id={conversation_id}")
        return conversation_id
    print("[DL] start conversation")
    body, code, _ = http_post_json(f"{DIRECTLINE_BASE_URL}/v3/directline/conversations", {}, headers)
    if code not in (200, 201):
        raise RuntimeError(f"Start conversation failed: {code} {body}")
    conversation_id = json.loads(body.decode())["conversationId"]
    print(f"[DL] conversation started id={conversation_id}")
    return conversation_id

def dl_post_text(token, conversation_id_unused, text, user_id):
    """
    Her zaman yeni konuşma açar; tokens/generate'dan gelen conv_id'yi kullanmaz.
    Nedeni: bazı ortamlarda generate yanıtındaki conv_id ilk /activities POST'unda 404'a yol açabiliyor.
    """
    headers = {"Authorization": f"Bearer {token}"}

    # 1) Konuşmayı AÇ
    print("[DL] start conversation (always)")
    b_start, c_start, _ = http_post_json(f"{DIRECTLINE_BASE_URL}/v3/directline/conversations", {}, headers)
    if c_start not in (200, 201):
        print(f"[DL][ERR] start conversation failed status={c_start} body={b_start}")
        raise RuntimeError(f"Start conversation failed: {c_start} {b_start}")
    conv_id = json.loads(b_start.decode())["conversationId"]
    print(f"[DL] conversation started id={conv_id}")

    # 2) Mesajı gönder
    url = f"{DIRECTLINE_BASE_URL}/v3/directline/conversations/{conv_id}/activities"
    print(f"[DL] post text conv={conv_id} url={repr(url)} text_len={len(text)}")
    body, code, _ = http_post_json(
        url,
        {"type": "message", "from": {"id": user_id}, "text": text},
        headers
    )
    if code not in (200, 201):
        print(f"[DL][ERR] post text failed status={code} body={body}")
        raise RuntimeError(f"Post activity failed: {code} {body}")
    print("[DL] post text ok")
    return conv_id

def dl_upload_image(token, conversation_id_unused, filename, content_type, content_bytes, user_id, text):
    """
    Her zaman yeni konuşma açar ve /upload kullanır; başarısız olursa data URL fallback.
    """
    headers = {"Authorization": f"Bearer {token}"}
    
    # 1) Konuşmayı AÇ
    print("[DL] start conversation (always) for upload")
    b_start, c_start, _ = http_post_json(f"{DIRECTLINE_BASE_URL}/v3/directline/conversations", {}, headers)
    if c_start not in (200, 201):
        print(f"[DL][ERR] start conversation failed status={c_start} body={b_start}")
        raise RuntimeError(f"Start conversation failed: {c_start} {b_start}")
    conv_id = json.loads(b_start.decode())["conversationId"]
    print(f"[DL] conversation started id={conv_id} (for upload)")
    
    print(f"[DL] Message Text {text}")

    # 2) Upload denemesi
    activity = {
        "type": "message",
        "from": {"id": user_id},
        "text": text or ""#,
        #"attachments": [{
        #    "contentType": content_type,
        #    "name": filename
        #}]
    }
    
    activity_json = json.dumps(activity, ensure_ascii=False)

    fields = {
            "activity": (activity_json, None)
    }
    files  = [{
        "name":"file",
        "filename":filename,
        "content":content_bytes,
        "content_type":content_type
    }]
    upload_url = f"{DIRECTLINE_BASE_URL}/v3/directline/conversations/{conv_id}/upload?userId={urllib.parse.quote(user_id)}"
    print(f"[DL] upload image conv={conv_id} url={repr(upload_url)} file={filename} ctype={content_type} bytes={len(content_bytes)}")
    
    b_up, c_up, h_up = http_post_multipart(upload_url, fields, files, headers=headers, timeout=90)    

    if c_up in (200, 201):
        print("[DL] upload ok; text + attachment sent together??") 

    # Test: upload sonrası activities kontrolü
        b_act, c_act, h_act = http_get_json(
            f"{DIRECTLINE_BASE_URL}/v3/directline/conversations/{conv_id}/activities",
            headers=headers, timeout=30
        )
        acts = json.loads(b_act.decode("utf-8"))
        last = acts["activities"][-1]
        print("last.attachments:", last.get("attachments"))
        if last.get("attachments"):
            print("attachment[0].contentType:", last["attachments"][0].get("contentType"))
            print("attachment[0].contentUrl :", last["attachments"][0].get("contentUrl"))

        return conv_id
    
    # 3) Fallback: data URL
    print(f"[DL][WARN] upload failed status={c_up}; fallback to data URL")
    data_url = f"data:{content_type};base64,{base64.b64encode(content_bytes).decode()}"
    act_fb = {
        "type": "message",
        "from": {"id": user_id},
        "attachments": [{
            "contentType": content_type or "application/octet-stream",
            "contentUrl": data_url,
            "name": filename
        }]
    }
    if text:
        act_fb["text"] = text
    
    url_fb = f"{DIRECTLINE_BASE_URL}/v3/directline/conversations/{conv_id}/activities"
    print(f"[DL] fallback post (data URL) conv={conv_id} url={repr(url_fb)}")
    b_fb, c_fb, _ = http_post_json(url_fb, act_fb, headers)
    if c_fb not in (200, 201):
        print(f"[DL][ERR] fallback failed status={c_fb} body={b_fb}")
        raise RuntimeError(f"Upload failed ({c_up}); fallback failed ({c_fb}): {b_fb}")
    print("[DL] fallback (data URL) ok")
    return conv_id

def dl_poll_reply_text_and_attachments(token, conversation_id,
                                       max_wait_seconds=None,
                                       initial_interval=None,
                                       backoff_factor=None,
                                       max_interval=None,
                                       user_id_prefix="tg-"):
    """
    Adaptif (artırımlı) polling:
      - hızlı ilk denemeler
      - kademeli artan bekleme (exponential backoff) + küçük jitter
      - DL_MAX_WAIT_SECONDS penceresi boyunca bekler
    """
    headers = {"Authorization": f"Bearer {token}"}
    url = f"{DIRECTLINE_BASE_URL}/v3/directline/conversations/{conversation_id}/activities"

    # Varsayılanları ortamdan çek
    max_wait_seconds = float(max_wait_seconds or DL_MAX_WAIT_SECONDS)
    interval = float(initial_interval or DL_INITIAL_POLL_INTERVAL)
    factor = float(backoff_factor or DL_BACKOFF_FACTOR)
    max_interval = float(max_interval or DL_MAX_POLL_INTERVAL)

    deadline = time.time() + max_wait_seconds
    watermark = None
    replies = []
    attempt = 0

    print(f"[DL] poll replies (adaptive) conv={conversation_id} "
          f"max_wait={max_wait_seconds}s start_interval={interval}s backoff={factor} max_interval={max_interval}s")

    while time.time() < deadline:
        attempt += 1
        q = f"?watermark={urllib.parse.quote(watermark)}" if watermark else ""
        body, code, _ = http_get(url + q, headers, timeout=20)
        if code != 200:
            print(f"[DL] poll http status={code} (attempt={attempt}) -> stop polling")
            break

        obj = json.loads(body.decode())
        watermark = obj.get("watermark")
        activities = obj.get("activities", [])
        print(f"[DL] poll got activities={len(activities)} watermark={watermark} attempt={attempt}")

        for act in activities:
            if act.get("type") == "message" and not act.get("from", {}).get("id", "").startswith(user_id_prefix):
                text = act.get("text")
                atts = act.get("attachments") or []
                print(f"[DL] bot message text_len={len(text or '')} attachments={len(atts)}")
                replies.append({"text": text, "attachments": atts})

        if replies:
            print(f"[DL] poll done replies={len(replies)} in_attempts={attempt}")
            return replies

        # Adaptif bekleme + jitter
        jitter = random.uniform(-0.1, 0.1)  # +/- 100 ms
        sleep_for = max(0.1, min(max_interval, interval + jitter))
        now_left = max(0, deadline - time.time())
        sleep_for = min(sleep_for, now_left)
        print(f"[DL] no reply yet; sleeping {sleep_for:.2f}s (attempt={attempt})")
        time.sleep(sleep_for)

        # bir sonraki döngüde aralığı büyüt
        interval = min(max_interval, interval * factor)

    print("[DL] poll timeout/no replies (adaptive)")
    return replies

# -------- Security: optional secret_token check --------
def validate_telegram_secret(headers):
    if not REQUIRE_TG_SECRET:
        print("[SEC] REQUIRE_TG_SECRET=false -> skipping secret header validation")
        return True
    sent = headers.get("x-telegram-bot-api-secret-token") or headers.get("X-Telegram-Bot-Api-Secret-Token")
    ok = (TELEGRAM_SECRET_TOKEN and sent == TELEGRAM_SECRET_TOKEN)
    print(f"[SEC] secret header present={bool(sent)} match={ok}")
    return ok  # Telegram secret header opsiyoneldir; verildiyse doğrulanır. [1](https://learn.microsoft.com/en-us/azure/bot-service/rest-api/bot-framework-rest-direct-line-3-0-authentication?view=azure-bot-service-4.0)

# -------- Lambda Handler --------
def lambda_handler(event, context):
    t0 = time.time()
    print("="*80)
    print(f"[INVOKE] time={datetime.utcnow().isoformat()}Z "
          f"func_url=True method={event.get('requestContext',{}).get('http',{}).get('method')} "
          f"path={event.get('rawPath')} isBase64={event.get('isBase64Encoded')}")
    headers = { (k.lower() if isinstance(k,str) else k): v for k,v in (event.get("headers") or {}).items() }
    if not validate_telegram_secret(headers):
        print("[INVOKE] unauthorized (secret mismatch)")
        return {"statusCode": 401, "body": "unauthorized"}

    raw = event.get("body") or "{}"
    if event.get("isBase64Encoded"):
        import base64 as b64
        print("[INVOKE] decoding base64 body")
        raw = b64.b64decode(raw).decode("utf-8")

    try:
        update = json.loads(raw)
        print(f"[UPDATE] keys={list(update.keys())}")
    except Exception as ex:
        print(f"[ERROR] invalid json ex={ex}")
        return {"statusCode": 400, "body": "invalid json"}

    message = (update.get("message") or update.get("edited_message")) or {}
    
    # DEBUG: Print complete message structure
    print(f"[DEBUG] Complete message structure:")
    print(f"[DEBUG] message = {json.dumps(message, ensure_ascii=False, indent=2)}")
    
    chat = message.get("chat") or {}
    chat_id = chat.get("id")
    user_id = f"tg-{chat_id}"
    print(f"[CTX] chat_id={chat_id} user_id={user_id}")

    if not chat_id:
        print("[INVOKE] no chat -> 200")
        return {"statusCode": 200, "body": "no chat"}
    
    uid = str(message['from']['id'])
    # Handle /start command
    if 'text' in message and message['text'].startswith('/start'):
        user_name = message['from'].get('first_name', 'there')
        welcome_text = (
            f"Merhaba {user_name}! 👋\n\n"
            "Ben Adım Adım STK yardımcınızım. Bana metin mesajları veya resim gönderebilirsiniz.\n\n"
            "Size nasıl yardımcı olabilirim?"
        )
        tg_send_message(chat_id, welcome_text)
            
        return {
            'statusCode': 200,
            'body': json.dumps({'status': 'ok'})
        }    

    caption = message.get("caption")
    text = message.get("text")

    # Eğer ne text ne caption varsa, varsayılan prompt kullan
    if not caption and not text:
        caption = DEFAULT_PROMPT
        print(f"[FLOW] no caption/text -> using default prompt text_len={len(caption)}")
    else:
        if caption:
            print(f"[FLOW] caption detected text_len={len(caption)}")
        if text:
            print(f"[FLOW] text detected len={len(text)}")

    try:
        # 1) Token generate (SECRET -> TOKEN)
        token, conv_id = dl_get_token_and_conversation_via_secret()

        # 2) Metin mesajı (text veya caption varsa)
        message_to_send = text or caption  # text öncelikli, yoksa caption
        if message_to_send and message_to_send != DEFAULT_PROMPT:
            # DEFAULT_PROMPT değilse metin olarak gönder
            print(f"[FLOW] sending text message len={len(message_to_send)}")
            conv_id = dl_post_text(token, conv_id, message_to_send, user_id)

        # 3) Görsel
        photo_sizes = message.get("photo") or []
        doc = message.get("document")
        sent_image = False

        if photo_sizes:
            file_id = photo_sizes[-1]["file_id"]  # en büyük çözünürlük son eleman  [7](https://learn.microsoft.com/en-us/connectors/telegrambotip/)
            print(f"[FLOW] photo detected file_id={file_id}")
            download_url, file_path = tg_get_file(file_id)
            img_bytes, content_type = tg_download_file(download_url)
            if not content_type:
                content_type = mimetypes.guess_type(file_path)[0] or "image/jpeg"
            filename = os.path.basename(file_path) or f"photo_{int(time.time())}.jpg"
            # Görsel varsa caption kullan (yoksa DEFAULT_PROMPT)
            conv_id = dl_upload_image(token, conv_id, filename, content_type, img_bytes, user_id, caption or DEFAULT_PROMPT)
            sent_image = True

        elif doc and isinstance(doc, dict) and str(doc.get("mime_type","")).startswith("image/"):
            mime = doc.get("mime_type", "")
            print(f"[FLOW] document detected mime={mime}")
            if mime.startswith("image/"):
                file_id = doc["file_id"]
                download_url, file_path = tg_get_file(file_id)
                img_bytes, content_type = tg_download_file(download_url)
                if not content_type:
                    content_type = mimetypes.guess_type(file_path)[0] or "image/jpeg"
                filename = os.path.basename(file_path) or f"image_{int(time.time())}"
                conv_id = dl_upload_image(token, conv_id, filename, content_type, img_bytes, user_id, caption)
                sent_image = True

        # 4) Bot yanıtlarını topla
        replies = dl_poll_reply_text_and_attachments(token, conv_id, max_wait_seconds=30)
        if not replies:
            msg = "Güncel yanıt bulunamadı, lütfen tekrar deneyin." if not sent_image else \
                  "Görsel alındı, yanıt hazırlanıyor."
            tg_send_message(chat_id, msg)
            dt = time.time() - t0
            print(f"[DONE] no replies total_ms={int(dt*1000)}")
            return {"statusCode": 200, "body": "ok"}

        # 5) Yanıtları Telegram'a gönder
        for idx, r in enumerate(replies, 1):
            print(f"[REPLY] #{idx} text_len={len(r.get('text') or '')} atts={len(r.get('attachments') or [])}")
            if r.get("text"):
                tg_send_message(chat_id, r["text"])
            for a in (r.get("attachments") or []):
                curl = a.get("contentUrl")
                ctype = a.get("contentType", "")
                name = a.get("name") or ""
                print(f"[REPLY-ATT] type={ctype} url_present={bool(curl)} name={name}")
                if curl and curl.startswith("http") and ctype.startswith("image/"):
                    tg_send_photo_by_url(chat_id, curl, caption=name)

    except Exception as ex:
        print(f"[ERROR] flow ex={ex}")
        tg_send_message(chat_id, f"Bir hata oluştu ({ex}). Lütfen tekrar deneyiniz.")

    dt = time.time() - t0
    print(f"[DONE] total_ms={int(dt*1000)}")
    return {"statusCode": 200, "body": "ok"}
