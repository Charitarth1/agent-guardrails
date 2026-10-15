#!/usr/bin/env bash
# Offline supply-chain scanner for third-party agent skills, plugins and MCP servers.
# Runs Cisco skill-scanner + NVIDIA SkillSpector (pinned SHAs) fully OFFLINE and
# merges the results into one triage. Exit 2 = hard signal (route to Reviewer); 0 = clean.
#
# Usage:  scan_skills.sh <skills_dir> [out_dir]
#
# Offline policy: NEVER enable the LLM / VirusTotal / AI-Defense / OSV engines —
# they upload scanned content off-machine. This wrapper unsets their keys so the
# scanners cannot phone home even if keys exist in the environment.
set -euo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TARGET="${1:-}"
[ -n "$TARGET" ] || { echo "usage: $(basename "$0") <skills_dir> [out_dir]" >&2; exit 64; }
[ -d "$TARGET" ] || { echo "error: '$TARGET' is not a directory" >&2; exit 64; }
OUT="${2:-$HERE/reports/$(date +%Y%m%d-%H%M%S)}"
mkdir -p "$OUT"

UV="${UV:-uv}"
command -v "$UV" >/dev/null 2>&1 || UV="$(command -v uv || true)"
[ -n "$UV" ] || { echo "error: uv not found (needed to bootstrap scanners)" >&2; exit 69; }

VENVS="$HERE/.venvs"; CLONES="$HERE/.clones"
CISCO_URL="https://github.com/cisco-ai-defense/skill-scanner.git"
CISCO_SHA="48f59347a54b93606dd1e31c41989ebfd0fcc84d"
SS_URL="https://github.com/nvidia/skillspector.git"
SS_SHA="2bc641fd0639550a1cae9557491f483e30520afb"

ensure() { # name url sha binary
  local name="$1" url="$2" sha="$3" bin="$4"
  local venv="$VENVS/$name" clone="$CLONES/$name"
  if [ -x "$venv/bin/$bin" ]; then return 0; fi
  echo "[bootstrap] installing $name @ ${sha:0:7} (first run only)..." >&2
  rm -rf "$clone"; git clone --quiet "$url" "$clone"
  git -C "$clone" checkout --quiet "$sha"
  "$UV" venv --python 3.12 "$venv" >/dev/null 2>&1
  "$UV" pip install --python "$venv/bin/python" --quiet "$clone" >/dev/null
}
ensure cisco "$CISCO_URL" "$CISCO_SHA" skill-scanner
ensure skillspector "$SS_URL" "$SS_SHA" skillspector

# offline enforcement: strip every cloud/LLM key from the child environment
OFFLINE=(env -u VIRUSTOTAL_API_KEY -u AI_DEFENSE_API_KEY -u SKILL_SCANNER_LLM_API_KEY
         -u OPENAI_API_KEY -u ANTHROPIC_API_KEY -u NVIDIA_INFERENCE_KEY
         -u SKILLSPECTOR_PROVIDER SKILLSPECTOR_LOG_LEVEL=ERROR)

echo "[scan] Cisco skill-scanner (static, offline)..." >&2
"${OFFLINE[@]}" "$VENVS/cisco/bin/skill-scanner" scan-all "$TARGET" --recursive \
  --format json --output-json "$OUT/cisco_report.json" >/dev/null 2>&1 || true

echo "[scan] NVIDIA SkillSpector (static, --no-llm)..." >&2
"${OFFLINE[@]}" "$VENVS/skillspector/bin/skillspector" scan "$TARGET" --recursive \
  --no-llm --format json --output "$OUT/skillspector_report.json" >/dev/null 2>&1 || true

echo "[merge] building triage -> $OUT/SCAN_FINDINGS.md" >&2
set +e
python3 "$HERE/merge_findings.py" "$OUT/cisco_report.json" "$OUT/skillspector_report.json" \
  --out "$OUT/SCAN_FINDINGS.md"
rc=$?
set -e
echo "----"
sed -n '/## VERDICT/,$p' "$OUT/SCAN_FINDINGS.md" 2>/dev/null || true
echo "reports: $OUT"
exit "$rc"
