# Skill scanner

Offline supply-chain check for third-party agent **skills, plugins and MCP servers**, run before they are installed or granted to any agent. A skill is a set of instructions your agent will follow, so a malicious one is a prompt injection you installed on purpose.

It wraps two open-source scanners, pinned to exact commits, and merges their output into one triage.

| Scanner | Repo | Pinned commit | Engines used |
|---|---|---|---|
| Cisco skill-scanner | `github.com/cisco-ai-defense/skill-scanner` | `48f5934` | static, YARA, command taint |
| NVIDIA SkillSpector | `github.com/nvidia/skillspector` | `2bc641f` | static, AST (`--no-llm`) |

Both are Apache-2.0 and are cloned and installed on first run (not vendored here). Bumping a commit is a deliberate change: update the table and re-run.

## Usage

```bash
./scan_skills.sh <skills_dir> [out_dir]
```

| Exit code | Meaning |
|---|---|
| 0 | No hard signal |
| 2 | Hard signal (live secret, suspicious host, real obfuscation): send to a human reviewer |
| 64 / 69 | Usage error / `uv` not found |

Output: `cisco_report.json`, `skillspector_report.json` and `SCAN_FINDINGS.md` in the output directory.

## Offline only

Both scanners have optional engines (LLM review, VirusTotal, cloud APIs) that upload the scanned content. Pointing those at private material is the exfiltration this kit exists to prevent. The wrapper removes every cloud and LLM key from the scanners' environment, and the cloud engines stay off. Don't add `--use-llm`, `--use-virustotal` or similar flags.

## Reading the results

On a library of *security* skills, most findings describe the skill's subject, not a backdoor: a skill about credential theft legitimately contains credential-access code. `merge_findings.py` separates findings the topic explains from anomalies it doesn't:

- live or high-entropy secrets that aren't placeholders
- URLs to IP addresses, link shorteners, tunnels or throwaway TLDs
- real obfuscation (not YAML front matter misread as a binary)

Only those hard-block. Everything else becomes a shortlist for a human or a separate reviewer model.
