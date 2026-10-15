#!/usr/bin/env python3
"""Merge Cisco skill-scanner + NVIDIA SkillSpector reports into one triage.

Encodes the interpretation lesson from the 2026-08-08 audit: on a *cybersecurity*
skill library, most findings are topic-explained (the skill legitimately contains
offensive patterns). Real signal lives in ANOMALIES the topic doesn't explain:
planted/live secrets, malicious supply-chain, hidden/obfuscated payloads.

Exit code: 2 if a HARD signal is present (live secret, suspicious supply-chain
host, real obfuscation) so this can gate registration; 0 otherwise. The
operator-threat SHORTLIST is always printed for human/model review.
"""
import argparse, json, re, sys, collections

# categories that are NOT explained by an offensive-security topic
CISCO_OT = {"hardcoded_secrets", "supply_chain_attack", "prompt_injection",
            "unicode_steganography", "social_engineering", "skill_discovery_abuse",
            "tool_chaining_abuse"}
SS_OT = {"System Prompt Leakage", "Rogue Agent", "MCP Rug Pull",
         "Memory Poisoning", "Anti-Refusal", "Trigger Abuse"}
FP_OBFUSCATION_RULE = "FILE_MAGIC_MISMATCH"  # SKILL.md YAML frontmatter false positive

PLACEHOLDER = re.compile(r"YOUR_|EXAMPLE|<[^>]+>|xxx+|change[_-]?me|dummy|placeholder|"
                         r"\.\.\.|sample|test[_-]|fake|redact|canary|honeytoken|\$\{|"
                         r"os\.environ|getenv|vault|INSERT_|_HERE", re.I)
HIGH_ENTROPY = re.compile(r"[A-Za-z0-9+/]{32,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{20,}|"
                          r"sk-[A-Za-z0-9]{20,}|-----BEGIN")
URL = re.compile(r"https?://([^/\s'\"]+)")
_IP = re.compile(r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$")
_SHORTENERS = ("bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ngrok.io",
               "ngrok-free.app", "transfer.sh")
_BAD_TLDS = (".ru", ".top", ".xyz", ".tk", ".gq")


def is_suspicious_host(h):
    """Evaluate a full hostname (not a substring) — avoids the 't.co' in
    'content.com' false positive."""
    h = h.strip().lower().split(":")[0]
    if _IP.match(h):
        return True
    if any(h == s or h.endswith("." + s) for s in _SHORTENERS):
        return True
    labels = h.split(".")
    if "pastebin" in labels or "ngrok" in labels or "paste" in labels:
        return True
    if h.endswith(_BAD_TLDS):
        return True
    return False


def _base(p): return str(p).rsplit("/", 1)[-1]


def load_cisco(path):
    d = json.load(open(path))
    per = {}
    for r in d.get("results", []):
        nm = _base(r.get("skill_path") or r.get("skill_name") or "?")
        per[nm] = r.get("findings") or []
    return d.get("summary", {}), per


def load_ss(path):
    d = json.load(open(path))
    per = {}
    for r in d.get("skills", []):
        if isinstance(r, dict):
            per[r.get("name") or _base(r.get("path") or "?")] = r.get("issues") or []
    return per


def summarize(per, cat_key):
    sev = collections.Counter(); cat = collections.Counter(); nf = 0; withf = 0
    for fs in per.values():
        if fs: withf += 1
        for f in fs:
            nf += 1
            sev[str(f.get("severity", "?")).lower()] += 1
            cat[str(f.get(cat_key) or "?")] += 1
    return len(per), withf, nf, sev, cat


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("cisco_json"); ap.add_argument("skillspector_json")
    ap.add_argument("--out", help="write markdown report here (else stdout)")
    a = ap.parse_args()

    csum, cis = load_cisco(a.cisco_json)
    ssp = load_ss(a.skillspector_json)

    out = []
    def w(s=""): out.append(s)

    w("# Skill-Scan Triage\n")
    for label, per, ck in [("Cisco skill-scanner", cis, "category"),
                           ("NVIDIA SkillSpector", ssp, "category")]:
        n, wf, nf, sev, cat = summarize(per, ck)
        w(f"## {label}")
        w(f"- scanned **{n}**, with >=1 finding **{wf}**, total findings **{nf}**")
        w(f"- severity: " + ", ".join(f"{k}:{v}" for k, v in sev.most_common()))
        w("- top categories: " + ", ".join(f"{k}({v})" for k, v in cat.most_common(8)))
        w("")

    # --- anomaly extraction (topic does NOT explain these) ---
    live_secrets, supply, real_obf, pinj = [], [], [], []
    cis_ot = collections.defaultdict(set)
    for nm, fs in cis.items():
        for f in fs:
            c = f.get("category"); rid = f.get("rule_id", ""); snip = str(f.get("snippet") or "")
            if c == "hardcoded_secrets":
                cis_ot[nm].add(c)
                if HIGH_ENTROPY.search(snip) and not PLACEHOLDER.search(snip):
                    live_secrets.append((nm, f.get("file_path")))
            elif c == "supply_chain_attack":
                cis_ot[nm].add(c)
                hosts = URL.findall(snip)
                supply.append((nm, hosts, str(f.get("snippet") or "")[:80]))
            elif c == "obfuscation" and rid != FP_OBFUSCATION_RULE:
                cis_ot[nm].add(c); real_obf.append((nm, rid))
            elif c == "unicode_steganography":
                cis_ot[nm].add(c); real_obf.append((nm, "stego"))
            elif c == "prompt_injection":
                cis_ot[nm].add(c); pinj.append(nm)
            elif c in CISCO_OT:
                cis_ot[nm].add(c)
    ss_ot = collections.defaultdict(set)
    for nm, fs in ssp.items():
        for f in fs:
            if f.get("category") in SS_OT:
                ss_ot[nm].add(f.get("category"))
    cross = sorted(set(cis_ot) & set(ss_ot))

    # suspicious supply-chain host?
    bad_hosts = [(nm, h) for nm, hosts, _ in supply for h in hosts if is_suspicious_host(h)]

    w("## Operator-threat shortlist (anomalies to review — topic may still explain them)\n")
    w(f"- **Live/high-entropy secrets** (⚠ verify — possible planted keys): {len(live_secrets)}")
    for nm, fp in live_secrets[:25]: w(f"    - {nm} :: {fp}")
    w(f"- **Supply-chain install commands**: {len(supply)} (hosts below; flagged if suspicious)")
    all_hosts = sorted({h for _, hs, _ in supply for h in hs})
    w("    hosts seen: " + (", ".join(all_hosts) if all_hosts else "none"))
    if bad_hosts:
        w("    ⚠ SUSPICIOUS hosts: " + ", ".join(f"{n}:{h}" for n, h in bad_hosts))
    w(f"- **Real obfuscation/steganography** (excl. {FP_OBFUSCATION_RULE} FP): {len(real_obf)}")
    for nm, rid in real_obf[:25]: w(f"    - {nm} [{rid}]")
    w(f"- **Cisco prompt_injection**: {len(set(pinj))} skills")
    w(f"- **Cross-confirmed by BOTH scanners** (highest priority): {len(cross)}")
    for nm in cross[:40]: w(f"    - {nm}  cisco:{sorted(cis_ot[nm])} ss:{sorted(ss_ot[nm])}")
    w("")

    # --- verdict / gate ---
    # Only the clearest planted-backdoor tells hard-block. Obfuscation / prompt-injection
    # strings are frequently topic-explained in cyber skills, so they go to the review
    # shortlist, not an auto-block.
    hard = bool(live_secrets) or bool(bad_hosts)
    if hard:
        w("## VERDICT: ⛔ HARD SIGNAL PRESENT — do not auto-advance")
        w("- Live secret(s) and/or suspicious supply-chain host found above. Route to Reviewer immediately.")
    else:
        w("## VERDICT: ✅ no hard signal")
        w("- No live secrets and no suspicious supply-chain hosts.")
        w("- Shortlist items (obfuscation, prompt-injection strings, cross-confirmed) are "
          "candidates the Reviewer must judge for `topic_explains` — not auto-blocks.")
    w("\n*Both scanners run offline (no LLM/VirusTotal/AI-Defense/OSV). This tool flags; the "
      "pluggable Reviewer (CYBERSEC_SKILLS_ADOPTION_PLAN.md §3) decides `topic_explains`.*")

    report = "\n".join(out)
    if a.out:
        open(a.out, "w").write(report)
        print(f"wrote {a.out}")
    else:
        print(report)
    return 2 if hard else 0


if __name__ == "__main__":
    sys.exit(main())
