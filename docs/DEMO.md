# Live demonstration script

This is a run sheet for demonstrating the repository to an audience, for example
Malaysian government officers. The goal is to show that one sentence to an AI coding
agent is enough to check a domain (a name such as jpa.gov.my) or audit a server.

The method is MGv6C-1.0 (Malaysian Government IPv6 Compliance, version 1.0), the
standard used by the National IPv6 Readiness Monitor at https://ipv6.my6.my. IPv6
(Internet Protocol version 6) is the newer version of the addressing system that
lets devices find each other on the internet. It succeeds IPv4 (version 4), the
older system whose addresses are running out. The checks measure whether a service
still works when reached over IPv6.

The demonstration has two parts. Scenario A checks a domain. Scenario B audits the
server. Both work from a single sentence because the agent reads `AGENTS.md`.

## Before the audience arrives

Do these once, on the machine you will present from.

1. Open a terminal in the repository directory.
2. Confirm Python is present: `python3 --version`. It must be 3.8 or newer.
3. Confirm the machine has working IPv6 by running the checker once:

   ```bash
   python3 scripts/ipv6check.py my6.my --official
   ```

   You should see a score near 95 and the level "Compliant: fully ready", with the
   official score beside it. If you instead see PROVISIONAL, the room's network has
   no IPv6. Read the section below on that case before you present.
4. Optionally run the server audit once so you know what it will show:

   ```bash
   bash scripts/server-audit.sh
   ```
5. Have the agent tools ready: Claude Code, Codex CLI and Gemini CLI. Each reads the
   repository instructions automatically. Claude Code reads `CLAUDE.md`, Gemini CLI
   reads `GEMINI.md` and Codex CLI reads `AGENTS.md`. All three point to `AGENTS.md`.

A note on timing: a domain check usually finishes in a few seconds. A domain whose
IPv6 path is filtered can take longer while connections time out. The whole run has a
hard limit of 60 seconds. If that limit is reached, any unfinished check is shown as
NOT MEASURED with the reason "time limit reached", never as a failure.

## Scenario A: check a domain

Give the agent one sentence. Pick the tool you are demonstrating.

- **Claude Code:** "Read AGENTS.md and check the IPv6 readiness of jpa.gov.my, then explain the result to me."
- **Codex CLI:** "Follow AGENTS.md and run the IPv6 readiness check for my6.my with the official score, then summarise it."
- **Gemini CLI:** "Using AGENTS.md, check whether pos.com.my is IPv6 ready and tell me what to fix."

### What the audience should see

The agent runs `scripts/ipv6check.py` and then reports, in this order:

1. A verdict line with the score out of 100 and the level.
2. A numbered "What to fix" list, each item with one plain sentence on why it matters.
3. The evidence table with every check marked PASS, FAIL, NOT MEASURED or INFO.

Good domains to show contrast:

- `my6.my` is fully ready, scoring about 95. It shows what "Compliant" looks like.
- `jpa.gov.my` is partially compliant, scoring about 63. It shows a realistic "What
  to fix" list, because its web server does not answer over IPv6.
- `pos.com.my` is fully ready and shows a clean pass.

Scores can move by a point or two with network conditions. That is normal. If you
used `--official`, point out that the local score sits beside the official monitor
score, so the audience can compare the method with ipv6.my6.my.

### What to say

"This is the same method the National IPv6 Readiness Monitor uses. The agent ran 22
checks across the website, DNS (the Domain Name System, which turns names into
addresses), email and the existing IPv4 service, then weighted them and produced a
score. The verdict comes first, then exactly what to fix, then the evidence for every
check. Nothing was changed on the target, and nothing was sent anywhere except the
DNS lookups, the probes to that domain and the short check that this computer itself
has IPv6."

## Scenario B: audit this server

Give the agent one sentence.

- **Claude Code:** "Follow AGENTS.md and audit this server for IPv6 readiness, then show me the public hostnames it finds."
- **Codex CLI:** "Read AGENTS.md, run the read-only server audit and report this server's IPv6 readiness."
- **Gemini CLI:** "Using AGENTS.md, audit this machine for IPv6 readiness and tell me the blockers and gaps."

### What the audience should see

The agent runs `scripts/server-audit.sh`, reads the labelled sections and the
findings, then shows the public hostnames and runs scenario A on the ones the user
confirms. It reports:

1. A verdict for the server.
2. What to fix, grouped as blockers, gaps and notes, each with an evidence line.
3. A table of the public hostnames with their scenario A scores.
4. The server evidence and a capable, activated and tested table.

### What to say

"This audit is strictly read-only. It changed no setting, installed nothing and
restarted nothing. It never used sudo, the command that grants administrator rights.
Where it would need root, the administrator account, to see more, such as the
firewall rules that say which connections are allowed or blocked, it says 'needs
root to read' and carries on. It also never prints passwords, keys or tokens. The
agent then checked the public hostnames the user confirmed, so we get both the
inside view of the server and the outside view of its domains."

Emphasise the three terms: a service can be capable and activated but still not
tested. Only a passed test counts as ready.

## If the room has no IPv6 (the PROVISIONAL case)

Some venues have no IPv6. The repository handles this honestly, and it is worth
showing rather than hiding.

If the machine has no working outbound IPv6, the checker reports every IPv6
connection check as NOT MEASURED, marks the score PROVISIONAL and says so plainly.
It does not call those checks failed.

You can demonstrate this on purpose, even on a machine that has IPv6, by setting a
switch:

```bash
IPV6CHECK_FORCE_NO_V6=1 python3 scripts/ipv6check.py my6.my
```

### What to say

"This computer has no working outbound IPv6, so the checks that need an IPv6
connection were not measured. They are shown as NOT MEASURED, not as failures, and
the score is marked PROVISIONAL. This is the principle that not measured is not
failed: we will not count a gap we could not actually test against the domain. To
get a full result, run from a network with IPv6, or compare against the official
monitor with --official."

Then show the official comparison, which still works over IPv4:

```bash
IPV6CHECK_FORCE_NO_V6=1 python3 scripts/ipv6check.py my6.my --official
```

Point out that the DNS-based checks and the official score are still available,
because DNS over HTTPS and the official API (the monitor's machine-readable web
interface) work over IPv4.

## Fallback if an agent is slow or offline

If a tool hesitates, run the commands yourself and narrate. The result is the same.

```bash
python3 scripts/ipv6check.py jpa.gov.my --official
bash scripts/server-audit.sh --json
```

The second command also writes `ipv6-audit.json`, which you can open to show the
machine-readable form.

## Closing line

"One sentence to the agent, a verdict first, a clear list of what to fix and
evidence for every check. The same method as the national monitor, safe to run and
readable by both people and machines."
