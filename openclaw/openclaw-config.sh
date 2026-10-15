#!/bin/sh
# Version-control an OpenClaw host config without leaking it.
#
# ~/.openclaw/openclaw.json carries real security posture: the exec and tool
# policy, the sandbox, the gateway secret reference, the channel allowlists.
# Untracked, an edit that widens the blast radius leaves no trace, and a host
# rebuild silently loses the hardening. This keeps a tracked copy in a repo.
#
# Two rules make that safe:
#
#   1. No secrets. Export REFUSES if any scalar in the live config looks like a
#      credential, or if gateway.auth.token is a literal instead of a secret
#      store reference. It fails closed: if it can't prove the file is clean,
#      it writes nothing.
#
#   2. No identifiers. Channel allowlist principals (e.g. a Telegram user ID)
#      are replaced with __NAME__ placeholders on export and restored from a
#      local, never-committed identifiers file. Export also refuses if any
#      identifier survives redaction.
#
# Usage:
#   openclaw-config.sh status     compare live against tracked (default)
#   openclaw-config.sh export     live -> tracked (scanned, redacted)
#   openclaw-config.sh diff       show what changed
#   openclaw-config.sh restore    tracked -> live (backs up first)
#
# Requires: jq, awk.
set -eu

LIVE="${OPENCLAW_CONFIG_PATH:-$HOME/.openclaw/openclaw.json}"
HERE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
TRACKED="${OPENCLAW_TRACKED_PATH:-$HERE/openclaw.json}"
IDENT="${OPENCLAW_IDENTIFIERS:-$HERE/identifiers.local}"   # gitignored, mode 0600

TMP=$(mktemp)
trap 'rm -f "$TMP"' EXIT INT TERM

require_ident() {
  [ -f "$IDENT" ] || {
    echo "Missing $IDENT" >&2
    echo "Create it with one NAME=VALUE per line, e.g.:" >&2
    echo "  TELEGRAM_OWNER_ID=<numeric id>" >&2
    exit 1
  }
}

# Literal (not regex) replacement of every occurrence of $1 with $2. Values
# pass through the environment, so characters like | / & . * in an identifier
# can't break or widen the match the way they would inside a sed expression.
replace_all() {
  FROM="$1" TO="$2" awk '
    BEGIN { f = ENVIRON["FROM"]; t = ENVIRON["TO"] }
    {
      out = ""; s = $0
      while ((i = index(s, f)) > 0) { out = out substr(s, 1, i - 1) t; s = substr(s, i + length(f)) }
      print out s
    }'
}

# Refuse anything that looks like a credential. Checks every scalar, not just
# known paths, so a new secret in a new section is caught by default.
scan_for_secrets() {
  file="$1"
  if jq -e '.gateway.auth.token | type == "string"' "$file" >/dev/null 2>&1; then
    echo "REFUSING: gateway.auth.token is a literal, not a secret store reference." >&2
    return 1
  fi
  hits=$(jq -r 'paths(scalars) as $p | [($p|join(".")), (getpath($p)|tostring)] | @tsv' "$file" \
    | LC_ALL=C grep -iE 'sk-[a-zA-Z0-9]|AIza[0-9A-Za-z_-]|ghp_|github_pat_|xox[baprs]-|-----BEGIN|[0-9]{8,10}:[A-Za-z0-9_-]{30,}|[a-f0-9]{40,}' \
    || true)
  if [ -n "$hits" ]; then
    echo "REFUSING: credential-shaped values found. Nothing was written." >&2
    echo "$hits" | cut -f1 | sed 's/^/  at /' >&2   # paths only, never values
    return 1
  fi
}

# direction: redact (VALUE -> __NAME__) or unredact (__NAME__ -> VALUE)
swap_identifiers() {
  direction="$1"
  require_ident
  content=$(cat)
  while IFS='=' read -r name value; do
    case "$name" in ''|'#'*) continue ;; esac
    [ -n "$value" ] || continue
    if [ "$direction" = redact ]; then
      content=$(printf '%s\n' "$content" | replace_all "$value" "__${name}__")
    else
      content=$(printf '%s\n' "$content" | replace_all "__${name}__" "$value")
    fi
  done < "$IDENT"
  printf '%s\n' "$content"
}

case "${1:-status}" in
  export)
    scan_for_secrets "$LIVE"
    swap_identifiers redact < "$LIVE" > "$TMP"
    # Redaction must be total: a surviving identifier means the map is
    # incomplete, and shipping it would defeat the point.
    while IFS='=' read -r name value; do
      case "$name" in ''|'#'*) continue ;; esac
      [ -n "$value" ] || continue
      if LC_ALL=C grep -qF -- "$value" "$TMP"; then
        echo "REFUSING: $name still appears literally after redaction. Nothing was written." >&2
        exit 1
      fi
    done < "$IDENT"
    mkdir -p "$(dirname "$TRACKED")"
    cp "$TMP" "$TRACKED"
    echo "Exported -> $TRACKED (scanned clean, identifiers redacted)"
    ;;

  diff)
    [ -f "$TRACKED" ] || { echo "No tracked copy yet. Run: $0 export" >&2; exit 1; }
    swap_identifiers redact < "$LIVE" > "$TMP"
    diff -u "$TRACKED" "$TMP" && echo "No difference."
    ;;

  restore)
    [ -f "$TRACKED" ] || { echo "No tracked copy to restore from." >&2; exit 1; }
    printf 'Overwrite %s from the tracked copy? Type RESTORE: ' "$LIVE"
    read -r reply
    [ "$reply" = "RESTORE" ] || { echo "Aborted."; exit 1; }
    umask 077
    cp -p "$LIVE" "$LIVE.pre-restore"
    swap_identifiers unredact < "$TRACKED" > "$TMP"
    cp "$TMP" "$LIVE"
    chmod 600 "$LIVE" "$LIVE.pre-restore"
    echo "Restored. Previous config kept at $LIVE.pre-restore"
    echo "Verify with 'openclaw secrets audit --check' and 'openclaw gateway status' before trusting it."
    ;;

  status)
    [ -f "$TRACKED" ] || { echo "No tracked copy yet. Run: $0 export"; exit 0; }
    swap_identifiers redact < "$LIVE" > "$TMP"
    if cmp -s "$TRACKED" "$TMP"; then
      echo "In sync: live config matches $TRACKED"
    else
      echo "DRIFT: live config differs from the tracked copy. Run: $0 diff"
    fi
    ;;

  *)
    echo "Usage: $0 {status|export|diff|restore}" >&2
    exit 1
    ;;
esac
