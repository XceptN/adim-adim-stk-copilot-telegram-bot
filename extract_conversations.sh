#!/usr/bin/env bash
# extract_conversations.sh  v5
# Adım Adım STK Copilot Telegram Bot — CloudWatch log'larından konuşma geçmişi çeker
#
# Kullanım:
#   ./extract_conversations.sh                        # Son 7 gün (kısa)
#   ./extract_conversations.sh 1                      # Son 1 gün (kısa)
#   ./extract_conversations.sh --full                 # Son 7 gün (tam yanıtlar)
#   ./extract_conversations.sh --full 1               # Son 1 gün (tam yanıtlar)
#   ./extract_conversations.sh --full 2026-03-01 2026-03-23
#
# --full modu: Bot yanıtlarını tam olarak (çok satırlı) çeker.
#              Daha fazla API çağrısı yapar, daha yavaştır.
#
# Gereksinimler: aws cli, jq, python3

set -euo pipefail

PROFILE="${AWS_PROFILE:-adimadim}"
REGION="${AWS_REGION:-eu-north-1}"
LOG_GROUP="/aws/lambda/adim-adim-stk-copilot-telegram-bot"
OUTPUT_DIR="/tmp/tg-bot-logs"
mkdir -p "$OUTPUT_DIR"

# ── Argüman parse ──
FULL_MODE=false
POSITIONAL=()
for arg in "$@"; do
    case "$arg" in
        --full) FULL_MODE=true ;;
        *) POSITIONAL+=("$arg") ;;
    esac
done
set -- "${POSITIONAL[@]+"${POSITIONAL[@]}"}"

# ── Tarih aralığı ──
if [[ $# -eq 2 ]]; then
    START_MS=$(date -d "$1" +%s)000
    END_MS=$(date -d "$2 23:59:59" +%s)000
    LABEL="$1 → $2"
elif [[ $# -eq 1 ]]; then
    DAYS=$1
    START_MS=$(date -d "${DAYS} days ago" +%s)000
    END_MS=$(date +%s)000
    LABEL="son ${DAYS} gün"
else
    DAYS=7
    START_MS=$(date -d "${DAYS} days ago" +%s)000
    END_MS=$(date +%s)000
    LABEL="son ${DAYS} gün"
fi

MODE_LABEL="kısa"
$FULL_MODE && MODE_LABEL="TAM YANITLAR"

echo "══════════════════════════════════════════════════════════════"
echo "  Adım Adım STK Bot — Konuşma Geçmişi Çıkarıcı  (v5)"
echo "  Tarih aralığı : ${LABEL}"
echo "  Mod           : ${MODE_LABEL}"
echo "  Profil        : ${PROFILE}"
echo "  Region        : ${REGION}"
echo "══════════════════════════════════════════════════════════════"
echo ""

# ── Paginated fetch ──
fetch_all_events() {
    local filter_pattern="$1"
    local outfile="$2"
    local token=""
    local page=0
    local tmpfile
    tmpfile=$(mktemp)

    aws logs filter-log-events \
        --log-group-name "$LOG_GROUP" \
        --start-time "$START_MS" \
        --end-time "$END_MS" \
        --filter-pattern "$filter_pattern" \
        --output json \
        --profile "$PROFILE" \
        --region "$REGION" > "$tmpfile" 2>/dev/null

    jq '.events' "$tmpfile" > "$outfile"
    token=$(jq -r '.nextToken // empty' "$tmpfile")
    page=1

    while [[ -n "$token" ]]; do
        page=$((page + 1))
        echo "     sayfa ${page}..."
        aws logs filter-log-events \
            --log-group-name "$LOG_GROUP" \
            --start-time "$START_MS" \
            --end-time "$END_MS" \
            --filter-pattern "$filter_pattern" \
            --next-token "$token" \
            --output json \
            --profile "$PROFILE"  \
            --region "$REGION" > "$tmpfile" 2>/dev/null

        jq -s '.[0] + .[1]' "$outfile" <(jq '.events' "$tmpfile") > "${outfile}.tmp"
        mv "${outfile}.tmp" "$outfile"

        token=$(jq -r '.nextToken // empty' "$tmpfile")
    done

    rm -f "$tmpfile"
    local count
    count=$(jq 'length' "$outfile")
    echo "     ✓ ${page} sayfa, ${count} kayıt"
}

# ── Kullanıcı mesajları ──
RAW_USER="$OUTPUT_DIR/raw_user.json"
echo "⏳ [1/3] Kullanıcı mesajları çekiliyor..."
fetch_all_events '"[TG] User"' "$RAW_USER"

# ── Bot yanıtları ──
RAW_BOT="$OUTPUT_DIR/raw_bot.json"
echo "⏳ [2/3] Bot yanıtları çekiliyor..."
fetch_all_events '"[TG] Message sent to user"' "$RAW_BOT"

# ── Context satırları ──
RAW_CTX="$OUTPUT_DIR/raw_ctx.json"
echo "⏳ [3/3] Chat context bilgileri çekiliyor..."
fetch_all_events '"[CTX]"' "$RAW_CTX"

echo ""

# ══════════════════════════════════════════════════════════════
# FULL MODE: Bot yanıtlarının tam metnini çekmek için
# her yanıtın log stream'inden tüm satırları alıyoruz
# ══════════════════════════════════════════════════════════════
if $FULL_MODE; then
    echo "⏳ [FULL] Tam bot yanıtları çekiliyor..."

    # Bot yanıtlarının bulunduğu log stream'leri ve timestamp'leri çıkar
    # Her "[TG] Message sent to user" satırı bir logStreamName ve timestamp'e sahip
    STREAMS_FILE="$OUTPUT_DIR/bot_streams.json"
    jq '[.[] | {logStreamName, timestamp, eventId}] | unique_by(.logStreamName + "-" + (.timestamp|tostring))' \
        "$RAW_BOT" > "$STREAMS_FILE"

    STREAM_COUNT=$(jq 'length' "$STREAMS_FILE")
    echo "   ${STREAM_COUNT} yanıt log stream'i bulundu"

    # Her stream için full log'u çek ve "[TG] Message sent to user" ile
    # "END RequestId" arasındaki tüm satırları birleştir
    FULL_RESPONSES="$OUTPUT_DIR/full_responses.json"
    echo "[]" > "$FULL_RESPONSES"

    # Python ile daha verimli işleyelim
    FULL_SCRIPT="$OUTPUT_DIR/_extract_full.py"
    cat > "$FULL_SCRIPT" << 'PYEOF'
import json
import subprocess
import sys
import os

profile = sys.argv[1]
region = sys.argv[2]
log_group = sys.argv[3]
streams_file = sys.argv[4]
output_file = sys.argv[5]

with open(streams_file) as f:
    entries = json.load(f)

# Group by logStreamName to avoid duplicate fetches
from collections import defaultdict
stream_map = defaultdict(list)
for e in entries:
    stream_map[e["logStreamName"]].append(e["timestamp"])

results = []
total = len(stream_map)

for idx, (stream_name, timestamps) in enumerate(stream_map.items(), 1):
    print(f"     stream {idx}/{total}: {stream_name[:60]}...", flush=True)

    # Fetch the full log stream around the bot response timestamps
    # Use a window: earliest timestamp - 2s to latest + 1s
    min_ts = min(timestamps) - 2000
    max_ts = max(timestamps) + 1000

    cmd = [
        "aws", "logs", "get-log-events",
        "--log-group-name", log_group,
        "--log-stream-name", stream_name,
        "--start-time", str(min_ts),
        "--end-time", str(max_ts),
        "--start-from-head",
        "--output", "json",
        "--profile", profile,
        "--region", region
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        data = json.loads(proc.stdout)
        events = data.get("events", [])
    except Exception as ex:
        print(f"     ⚠ Hata: {ex}", flush=True)
        continue

    # Now reconstruct: find "[TG] Message sent to user:" lines
    # and collect all subsequent lines until END/START/[INFO]/[DEBUG] marker
    i = 0
    while i < len(events):
        msg = events[i].get("message", "")
        ts = events[i].get("timestamp", 0)

        if "[TG] Message sent to user:" in msg:
            # Start collecting: first line has the beginning of the response
            full_text_parts = [msg.rstrip("\n")]

            # Collect continuation lines
            j = i + 1
            while j < len(events):
                next_msg = events[j].get("message", "")
                next_ts = events[j].get("timestamp", 0)
                # Stop if we hit a known log marker or a new Lambda invocation
                if any(marker in next_msg for marker in [
                    "[INFO]", "[DEBUG]", "[ERROR]",
                    "END RequestId:", "REPORT RequestId:",
                    "START RequestId:", "INIT_START"
                ]):
                    break
                # Stop if timestamp jumps more than 2 seconds
                if next_ts - ts > 2000:
                    break
                full_text_parts.append(next_msg.rstrip("\n"))
                j += 1

            full_text = "\n".join(full_text_parts)
            results.append({
                "timestamp": ts,
                "logStreamName": stream_name,
                "full_message": full_text
            })
            i = j
        else:
            i += 1

results.sort(key=lambda x: x["timestamp"])

with open(output_file, "w") as f:
    json.dump(results, f, ensure_ascii=False, indent=2)

print(f"     ✓ {len(results)} tam yanıt çıkarıldı")
PYEOF

    python3 "$FULL_SCRIPT" "$PROFILE" "$REGION" "$LOG_GROUP" "$STREAMS_FILE" "$FULL_RESPONSES"
    echo ""
fi

# ══════════════════════════════════════════════════════════════
# Rapor oluşturma
# ══════════════════════════════════════════════════════════════

# Birleştir ve sırala
RAW_MESSAGES="$OUTPUT_DIR/raw_messages.json"
jq -s '.[0] + .[1] | sort_by(.timestamp) | unique_by(.eventId)' \
    "$RAW_USER" "$RAW_BOT" > "$RAW_MESSAGES"

REPORT="$OUTPUT_DIR/conversations.txt"
CSV_REPORT="$OUTPUT_DIR/conversations.csv"

echo "📋 Rapor oluşturuluyor..."

if $FULL_MODE; then
    # Full mode: Python ile user messages + full responses birleştir
    REPORT_SCRIPT="$OUTPUT_DIR/_build_report.py"
    cat > "$REPORT_SCRIPT" << 'PYEOF'
import json
import sys
import csv
from datetime import datetime, timezone

user_file = sys.argv[1]
full_resp_file = sys.argv[2]
txt_out = sys.argv[3]
csv_out = sys.argv[4]

with open(user_file) as f:
    user_events = json.load(f)
with open(full_resp_file) as f:
    full_responses = json.load(f)

# Build timeline
timeline = []

for ev in user_events:
    msg = ev["message"].rstrip("\n")
    ts = ev["timestamp"]
    # Parse: [INFO] [TG] User <Name> said: <text>
    marker = "[TG] User <"
    idx = msg.find(marker)
    if idx < 0:
        continue
    rest = msg[idx + len(marker):]
    gt = rest.find("> said: <")
    if gt < 0:
        continue
    user = rest[:gt]
    text = rest[gt + len("> said: <"):]
    if text.endswith(">"):
        text = text[:-1]
    timeline.append({
        "ts": ts,
        "type": "SORU",
        "user": user,
        "text": text
    })

for resp in full_responses:
    msg = resp["full_message"]
    ts = resp["timestamp"]
    # Extract text after "[TG] Message sent to user: <"
    marker = "[TG] Message sent to user: <"
    idx = msg.find(marker)
    if idx < 0:
        continue
    text = msg[idx + len(marker):]
    # Remove trailing ">" if it's the last char
    if text.endswith(">"):
        text = text[:-1]
    timeline.append({
        "ts": ts,
        "type": "YANIT",
        "user": "",
        "text": text
    })

timeline.sort(key=lambda x: x["ts"])

# Write TXT
with open(txt_out, "w", encoding="utf-8") as f:
    for item in timeline:
        dt = datetime.fromtimestamp(item["ts"] / 1000, tz=timezone.utc)
        ts_str = dt.strftime("%Y-%m-%d %H:%M:%S")
        icon = "📩 SORU " if item["type"] == "SORU" else "🤖 YANIT"
        user_col = item["user"] if item["user"] else "         "
        f.write(f"{ts_str} | {icon} | {user_col} | {item['text']}\n")
        if item["type"] == "YANIT":
            f.write("\n")  # blank line after responses for readability

# Write CSV
with open(csv_out, "w", encoding="utf-8", newline="") as f:
    writer = csv.writer(f, quoting=csv.QUOTE_ALL)
    writer.writerow(["Tarih", "Saat", "Yön", "Kullanıcı", "Mesaj"])
    for item in timeline:
        dt = datetime.fromtimestamp(item["ts"] / 1000, tz=timezone.utc)
        date_str = dt.strftime("%Y-%m-%d")
        time_str = dt.strftime("%H:%M:%S")
        # For CSV, replace newlines with spaces in response text
        text_flat = item["text"].replace("\n", " ↵ ")
        writer.writerow([date_str, time_str, item["type"], item["user"], text_flat])

print(f"   ✓ {len(timeline)} kayıt yazıldı")
PYEOF

    python3 "$REPORT_SCRIPT" "$RAW_USER" "$FULL_RESPONSES" "$REPORT" "$CSV_REPORT"

else
    # Short mode (v3 ile aynı)
    echo '"Tarih","Saat","Yön","Kullanıcı","Mesaj"' > "$CSV_REPORT"

    jq -r '
    .[]
    | .timestamp as $ts
    | (.message | rtrimstr("\n")) as $msg
    | ($ts / 1000 | strftime("%Y-%m-%d %H:%M:%S")) as $time
    | if ($msg | test("\\[TG\\] User <")) then
        ($msg | capture("\\[TG\\] User <(?<user>[^>]+)> said: <(?<text>.+)>$")
         // null)
        | if . then "\($time) | 📩 SORU  | \(.user) | \(.text)" else empty end
      elif ($msg | test("\\[TG\\] Message sent to user:")) then
        ($msg | capture("\\[TG\\] Message sent to user: <(?<text>.+)>$")
         // null)
        | if . then "\($time) | 🤖 YANIT |          | \(.text)" else empty end
      else
        empty
      end
    ' "$RAW_MESSAGES" 2>/dev/null > "$REPORT" || true

    jq -r '
    .[]
    | .timestamp as $ts
    | (.message | rtrimstr("\n")) as $msg
    | ($ts / 1000 | strftime("%Y-%m-%d")) as $date
    | ($ts / 1000 | strftime("%H:%M:%S")) as $time
    | if ($msg | test("\\[TG\\] User <")) then
        ($msg | capture("\\[TG\\] User <(?<user>[^>]+)> said: <(?<text>.+)>$")
         // null)
        | if . then
            "\"\($date)\",\"\($time)\",\"SORU\",\"\(.user)\",\"\(.text | gsub("\n"; " ") | gsub("\""; "\"\""))\""
          else empty end
      elif ($msg | test("\\[TG\\] Message sent to user:")) then
        ($msg | capture("\\[TG\\] Message sent to user: <(?<text>.+)>$")
         // null)
        | if . then
            "\"\($date)\",\"\($time)\",\"YANIT\",\"\",\"\(.text | gsub("\n"; " ") | gsub("\""; "\"\""))\""
          else empty end
      else
        empty
      end
    ' "$RAW_MESSAGES" 2>/dev/null >> "$CSV_REPORT" || true
fi

# ── Chat özeti ──
CHAT_SUMMARY="$OUTPUT_DIR/chat_summary.txt"
echo "── Aktif Chat'ler (mesaj sayısı / chat_id / tip) ──" > "$CHAT_SUMMARY"
jq -r '
.[]
| .message
| capture("\\[CTX\\] chat_id=(?<cid>[^ ]+) chat_type=(?<ctype>[^ ]+)")
| "\(.cid) (\(.ctype))"
' "$RAW_CTX" 2>/dev/null | sort | uniq -c | sort -rn >> "$CHAT_SUMMARY" || true

# ── Sonuç ──
CONV_LINES=$(wc -l < "$REPORT" 2>/dev/null | tr -d ' ')
CSV_LINES=$(($(wc -l < "$CSV_REPORT" 2>/dev/null | tr -d ' ') - 1))

echo ""
echo "══════════════════════════════════════════════════════════════"
echo "  ✅ Tamamlandı!"
echo ""
echo "  📄 Konuşma raporu : ${REPORT} (${CONV_LINES} satır)"
echo "  📊 CSV raporu     : ${CSV_REPORT} (${CSV_LINES} kayıt)"
echo "  🏠 Chat özeti     : ${CHAT_SUMMARY}"
echo "  📦 Ham veriler    : ${OUTPUT_DIR}/"
echo "══════════════════════════════════════════════════════════════"
echo ""
echo "── Son 30 konuşma satırı ──"
echo ""
tail -30 "$REPORT"
