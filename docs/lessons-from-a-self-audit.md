# Lessons from auditing my own agent stack

> **A note before the findings.** I'm not a security professional. My background is law, public policy and AI governance. I ran this adversarial audit with Claude (through Claude Code), using its cybersecurity capabilities to play the attacker against my own setup, and worked through the fixes with it. Read this as a practitioner's field notes, not a professional penetration test.

## Context

The setting is [OpenClaw](https://github.com/openclaw/openclaw), an open-source gateway that hosts AI agents and connects them to chat apps. At the end of August 2026 I was adding agents to my OpenClaw setup and preparing to move from the 2026.7 build to the 2.0 line (v2026.8.1), with the aim of running it as an always-on host I could message from my phone. Before connecting the chat channel, I stopped and audited what I had built. The audit ran against the 2026.7 build, shortly before the 2.0 upgrade.

**Scope.** The audit covered three things: the idea pipeline I built on top of OpenClaw (a phone chat that starts coding-agent work), the OpenClaw host and its tool policy, and the other projects on the same machine. It produced 17 findings: 16 in the original report, plus one found while fixing the others. The table below shows the ten I think teach the most.

The F-numbers in this repo's code comments refer to those findings. Details that would identify my machines, accounts or private folders are removed.

## Why this write-up lives next to the code

Every control in this repo exists because something specific failed. The hooks, the config tooling and the limitations page make more sense with their reasons beside them. Someone who only wants the DLP hook can skip this page. Someone deciding whether to trust it can see what it was built to stop, and what it still doesn't.

## The system

- Ideas arrive by voice or text from a phone chat (Telegram).
- A triage model classifies each one.
- A coding agent prepares a plan and a draft on an isolated git worktree.
- Nothing merges until I approve the diff at the terminal.

An always-on OpenClaw gateway on a VPS runs the chat agents. Claude Code runs the preparation step.

The whole design rests on one promise: **a chat message can start work, but only a human at a terminal can land it.**

## Verdict before fixes

The build was healthy, with tests passing and the type checks clean. The human-in-the-loop promise did not hold. Three independent defects each broke it, and they compounded each other.

| ID | Severity | Finding | Status |
|---|---|---|---|
| F-0 | Critical | The terminal-only "arm for approval" command was reachable from chat<br>*In plain terms:* The "are you sure?" step meant only for me at my keyboard could also be triggered from a chat message, so anyone who reached the chat could approve changes. | Fixed |
| F-1 | Critical | Path traversal in task IDs allowed arbitrary file read and write<br>*In plain terms:* A specially crafted task name could make the system read or overwrite files anywhere on the computer, not just in its own folder. | Fixed |
| F-5 | Critical | The chat agent's exec tool was not denied, so the tool policy, workspace limits and folder denylist could all be bypassed<br>*In plain terms:* I had locked several doors but left a master key in the agent's hand: it could run any command, which made the other restrictions meaningless. | Fixed, with one accepted trade-off |
| F-2 | High | Prompt injection: captured text flowed, unfenced, into a coding agent holding Bash and Write<br>*In plain terms:* A note sent from my phone could carry hidden instructions that a coding agent with full file and command access would then follow. | Fixed (three layers) |
| F-3 | High | The approval gate failed **open** on a malformed timestamp (a NaN comparison)<br>*In plain terms:* If the approval timer's date was garbled, the system treated the approval as still valid instead of expired. A broken check meant "yes" when it should have meant "no". | Fixed |
| F-10 | High | The private-folder denylist was enforced against file reads but not against Bash<br>*In plain terms:* The agent was blocked from opening my private folders one way, but could still open them by typing a command. | Fixed (three layers) |
| F-12 | High | A live bot token sat in a world-readable file outside every control<br>*In plain terms:* The password for my chat bot sat in a file that any program on the machine could read. | Fixed; token rotation is a manual step |
| F-13 | High | A second, older cloud ingress was still live<br>*In plain terms:* An older back door into the system was still open after I had built a new front door. | Closed at the entrance; cleanup of the old functions pending |
| F-14 | Medium | Three enforcement layers each held a different denylist<br>*In plain terms:* Three separate lists of off-limits folders had drifted apart, so a folder protected in one place was exposed in another. | Fixed (one source of truth plus a floor) |
| F-16 | Medium | Quoting a folder name (`'vault'`, `vault\ name`) slipped past the path check<br>*In plain terms:* Putting quote marks around a folder name was enough to slip past the check that should have blocked it. | Fixed |

## What I took away

Lessons 3 (second half) and 7 come from preparing this repo in October 2026, after the audit. The rest come from the August findings.

**1. A tool policy is only as strong as the exec tool (F-5, F-10).**
Denying the browser or restricting the file tools to the workspace means nothing if the agent can run `cat` or `curl` through a shell. The harness deny rules matched `Read(...)`, while the same file was one `Bash(cat ...)` away. The fix was layered: exec moved from `full` to an allowlist with deny on a miss, elevated tools were disabled, 25 tools were denied (up from 4), and the DLP hook in this repo now inspects commands as well as content.

**2. Human checkpoints must live outside the runtime that might be compromised (F-0).**
If the agent that reads untrusted chat text can also arm or approve, then one chat message becomes a merge. Arming, releasing quarantined input and approving are now terminal-only.

**3. Gates fail open in the boring places (F-3, plus a later find from October).**
`NaN < now` is false, so a malformed expiry looked like "not expired". Later, while preparing this repo, I found that a crashing hook exits with code 1, and Claude Code only blocks on exit code 2. A bug in the guard would have let the call through. Both now fail closed, and the crash case has a test.

**4. Fence untrusted text, then screen it deterministically (F-2).**
Captured text is wrapped in a per-call random delimiter it can't guess, so it can't move from data into instructions. A deterministic screen, which doesn't depend on a model behaving, flags credential paths, pushes, exfiltration and role overrides. Flagged items are quarantined with the text preserved, never silently rewritten. I verified it with a live injection attempt.

**5. Enforcement layers drift unless one feeds the others (F-14).**
The harness rules, the hook and the agent prompt each listed the protected folders separately, and a folder added to one was missing from another. Now one registry feeds all of them. The hook also keeps a built-in floor and takes the union, so a missing or truncated registry can only add coverage, never remove it.

**6. Pattern matchers need adversarial tests for both errors (F-16).**
Quoting a path defeated the regex. The regression suite now covers quoted, escaped and multi-segment forms. It also has as many "must allow" cases as "must block" ones, because a hook that blocks real work gets switched off.

**7. Redaction by hand drifts (found in October, not in the August audit).**
A config file I had labelled "sanitized" still held my chat ID, while the scripted export beside it was clean. Redaction belongs in a script that refuses to write when anything survives, as `openclaw/openclaw-config.sh` does.

## What you can take from this

**Seven questions to ask about your own agent setup.** Each one comes from a finding above.

1. What is the one promise your design rests on, and can a chat message break it? (F-0)
2. Can the agent that reads untrusted text also approve, publish or push? (F-0, F-2)
3. If you deny a tool, can the agent still reach the same thing through a shell? (F-5, F-10)
4. When a check gets bad input, does it answer yes or no? (F-3)
5. Is the list of off-limits folders written in one place, or several that can drift apart? (F-14)
6. Can a quoted, escaped or encoded version of a path get past your check? (F-16)
7. Where do your secrets live, and what else on the machine can read them? (F-12)

**Where to find each fix in this repo.**

| Finding | In this repo |
|---|---|
| F-10, F-16: folder rules bypassed through the shell or through quoting | [`claude-code/hooks/`](../claude-code/hooks/) |
| F-5: tool policy undone by an open exec tool | [`openclaw/`](../openclaw/) (hardened config and notes) |
| F-9, F-12: secrets in config and files | [`openclaw/openclaw-config.sh`](../openclaw/openclaw-config.sh) |
| Third-party skills as a supply chain | [`skill-scanner/`](../skill-scanner/) |

**What this is not.** It is one setup, audited once, by someone learning in public. It shows a method and a set of mistakes worth checking for. It doesn't certify anything.

## What I'd tell someone building the same thing

- Write down the one promise your design rests on, then attack that first.
- Assume the chat channel is hostile, even if you're the only member.
- Prefer controls that are code (a regex, a hash, a kernel sandbox) over controls that are instructions to a model.
- Test the "must allow" cases as hard as the "must block" ones.
