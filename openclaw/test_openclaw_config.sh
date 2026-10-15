#!/bin/sh
# Tests for openclaw-config.sh against synthetic configs. Requires jq.
set -eu
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fails=0
export OPENCLAW_CONFIG_PATH="$W/live.json" OPENCLAW_TRACKED_PATH="$W/tracked.json" OPENCLAW_IDENTIFIERS="$W/ids.local"

check() { # name, expected exit, command...
  name="$1"; want="$2"; shift 2
  set +e; "$@" >"$W/out" 2>&1; got=$?; set -e
  if [ "$got" -eq "$want" ]; then echo "PASS  $name"; else echo "FAIL  $name (exit=$got, want=$want)"; cat "$W/out"; fails=$((fails+1)); fi
}

# An identifier with regex/sed metacharacters must be replaced literally.
printf 'OWNER_ID=12.34|5*6\n' > "$W/ids.local"
cat > "$W/live.json" <<'JSON'
{"gateway":{"auth":{"token":{"source":"store","id":"GATEWAY_AUTH_TOKEN"}}},
 "channels":{"telegram":{"allowFrom":["12.34|5*6"],"note":"12x34|5*6 must stay"}}}
JSON
check "export with metacharacter identifier" 0 sh "$HERE/openclaw-config.sh" export
if grep -qF '12.34|5*6' "$W/tracked.json"; then echo "FAIL  identifier leaked"; fails=$((fails+1)); else echo "PASS  identifier redacted"; fi
if grep -qF '12x34|5*6 must stay' "$W/tracked.json"; then echo "PASS  look-alike text left alone (literal, not regex)"; else echo "FAIL  regex over-matched"; fails=$((fails+1)); fi
check "status reports in sync" 0 sh "$HERE/openclaw-config.sh" status
grep -q "In sync" "$W/out" && echo "PASS  in sync" || { echo "FAIL  not in sync"; fails=$((fails+1)); }

# A literal gateway token must refuse, and write nothing.
rm -f "$W/tracked.json"
printf '{"gateway":{"auth":{"token":"plaintext"}}}\n' > "$W/live.json"
check "refuses literal gateway token" 1 sh "$HERE/openclaw-config.sh" export
[ ! -e "$W/tracked.json" ] && echo "PASS  nothing written on refusal" || { echo "FAIL  wrote on refusal"; fails=$((fails+1)); }

# A Telegram-bot-token-shaped value anywhere must refuse.
printf '{"gateway":{"auth":{"token":{"source":"store"}}},"x":{"y":"123456789:AAH4synthetic_bot_token_value_000000"}}\n' > "$W/live.json"
check "refuses bot-token-shaped value" 1 sh "$HERE/openclaw-config.sh" export
grep -q "at x.y" "$W/out" && ! grep -q "AAH4synthetic" "$W/out" && echo "PASS  reports the path, not the value" || { echo "FAIL  leaked value in error"; fails=$((fails+1)); }

[ "$fails" -eq 0 ] && echo "=== ALL PASSED ===" || { echo "=== $fails FAILURE(S) ==="; exit 1; }
