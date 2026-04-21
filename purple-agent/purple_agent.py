#!/usr/bin/env python3
"""
purple_agent.py -- autonomous purple-team probe runner for the Suricata+Zeek lab.

Given attacker + sensor SSH endpoints and a victim IP, runs an LLM-driven
iterative loop:
  - pull candidate probes from a curated pool (probes.yaml)
  - baseline sensor, run probe from attacker, diff sensor, classify
  - log each attempt via a structured `record_finding` tool
  - stop when turn budget is exhausted or the agent signals completion
  - write an HTML report with MITRE ATT&CK mapping, methodology, and
    detection status per finding

Uses the Claude Agent SDK; auth comes from your Claude Code subscription
(the SDK inherits the OAuth token from the `claude` CLI, or falls back to
ANTHROPIC_API_KEY if you set one). Run `claude` once interactively to make
sure you're logged in before invoking this script.

Usage:
  python purple_agent.py \\
    --attacker-ip 34.x.x.x \\
    --sensor-ip 98.x.x.x \\
    --victim-ip 172.31.78.152 \\
    --key /path/to/lab.key \\
    [--budget 30] [--probe-pool probes.yaml]
"""

import argparse
import asyncio
import html as html_mod
import io
import json
import os
import re
import sys
from datetime import datetime, timezone
from pathlib import Path

# Force UTF-8 stdout/stderr so Unicode from the LLM doesn't explode on Windows
# charmap consoles.
if sys.stdout.encoding != "utf-8":
    sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8", errors="replace")
if sys.stderr.encoding != "utf-8":
    sys.stderr = io.TextIOWrapper(sys.stderr.buffer, encoding="utf-8", errors="replace")

try:
    from claude_agent_sdk import (
        ClaudeSDKClient,
        ClaudeAgentOptions,
        AssistantMessage,
        TextBlock,
        ToolUseBlock,
        ToolResultBlock,
        tool,
        create_sdk_mcp_server,
    )
except ImportError:
    print(
        "claude-agent-sdk not installed. Run: pip install -r requirements.txt",
        file=sys.stderr,
    )
    sys.exit(1)


SCRIPT_DIR = Path(__file__).parent.resolve()
REPORTS_DIR = SCRIPT_DIR / "reports"

# Ledger path is set per-run in run_agent() -- the record_finding tool reads it
# via this module-level var (simplest way to close over state with @tool).
_ledger_path: Path | None = None


# ============================================================================
#  MITRE ATT&CK lookup table
# ============================================================================

MITRE_LOOKUP = {
    "T1190": {"tactic": "Initial Access", "name": "Exploit Public-Facing Application", "url": "https://attack.mitre.org/techniques/T1190/"},
    "T1189": {"tactic": "Initial Access", "name": "Drive-by Compromise", "url": "https://attack.mitre.org/techniques/T1189/"},
    "T1195.002": {"tactic": "Initial Access", "name": "Supply Chain Compromise: Software Supply Chain", "url": "https://attack.mitre.org/techniques/T1195/002/"},
    "T1133": {"tactic": "Initial Access", "name": "External Remote Services", "url": "https://attack.mitre.org/techniques/T1133/"},
    "T1566.002": {"tactic": "Initial Access", "name": "Phishing: Spearphishing Link", "url": "https://attack.mitre.org/techniques/T1566/002/"},
    "T1059": {"tactic": "Execution", "name": "Command and Scripting Interpreter", "url": "https://attack.mitre.org/techniques/T1059/"},
    "T1059.004": {"tactic": "Execution", "name": "Command and Scripting Interpreter: Unix Shell", "url": "https://attack.mitre.org/techniques/T1059/004/"},
    "T1505.003": {"tactic": "Persistence", "name": "Server Software Component: Web Shell", "url": "https://attack.mitre.org/techniques/T1505/003/"},
    "T1078": {"tactic": "Defense Evasion", "name": "Valid Accounts", "url": "https://attack.mitre.org/techniques/T1078/"},
    "T1036": {"tactic": "Defense Evasion", "name": "Masquerading", "url": "https://attack.mitre.org/techniques/T1036/"},
    "T1001.003": {"tactic": "Command and Control", "name": "Data Obfuscation: Protocol Impersonation", "url": "https://attack.mitre.org/techniques/T1001/003/"},
    "T1071.001": {"tactic": "Command and Control", "name": "Application Layer Protocol: Web Protocols", "url": "https://attack.mitre.org/techniques/T1071/001/"},
    "T1071.004": {"tactic": "Command and Control", "name": "Application Layer Protocol: DNS", "url": "https://attack.mitre.org/techniques/T1071/004/"},
    "T1090": {"tactic": "Command and Control", "name": "Proxy", "url": "https://attack.mitre.org/techniques/T1090/"},
    "T1090.003": {"tactic": "Command and Control", "name": "Proxy: Multi-hop Proxy", "url": "https://attack.mitre.org/techniques/T1090/003/"},
    "T1105": {"tactic": "Command and Control", "name": "Ingress Tool Transfer", "url": "https://attack.mitre.org/techniques/T1105/"},
    "T1219": {"tactic": "Command and Control", "name": "Remote Access Software", "url": "https://attack.mitre.org/techniques/T1219/"},
    "T1572": {"tactic": "Command and Control", "name": "Protocol Tunneling", "url": "https://attack.mitre.org/techniques/T1572/"},
    "T1568.002": {"tactic": "Command and Control", "name": "Dynamic Resolution: Domain Generation Algorithms", "url": "https://attack.mitre.org/techniques/T1568/002/"},
    "T1528": {"tactic": "Credential Access", "name": "Steal Application Access Token", "url": "https://attack.mitre.org/techniques/T1528/"},
    "T1555.003": {"tactic": "Credential Access", "name": "Credentials from Password Stores: Web Browsers", "url": "https://attack.mitre.org/techniques/T1555/003/"},
    "T1558.004": {"tactic": "Credential Access", "name": "Steal or Forge Kerberos Tickets: AS-REP Roasting", "url": "https://attack.mitre.org/techniques/T1558/004/"},
    "T1552.001": {"tactic": "Credential Access", "name": "Unsecured Credentials: Credentials In Files", "url": "https://attack.mitre.org/techniques/T1552/001/"},
    "T1021.004": {"tactic": "Lateral Movement", "name": "Remote Services: SSH", "url": "https://attack.mitre.org/techniques/T1021/004/"},
    "T1210": {"tactic": "Lateral Movement", "name": "Exploitation of Remote Services", "url": "https://attack.mitre.org/techniques/T1210/"},
    "T1041": {"tactic": "Exfiltration", "name": "Exfiltration Over C2 Channel", "url": "https://attack.mitre.org/techniques/T1041/"},
    "T1048.001": {"tactic": "Exfiltration", "name": "Exfiltration Over Alternative Protocol: Symmetric Encrypted Non-C2", "url": "https://attack.mitre.org/techniques/T1048/001/"},
    "T1567": {"tactic": "Exfiltration", "name": "Exfiltration Over Web Service", "url": "https://attack.mitre.org/techniques/T1567/"},
    "T1567.002": {"tactic": "Exfiltration", "name": "Exfiltration Over Web Service: Exfil to Cloud Storage", "url": "https://attack.mitre.org/techniques/T1567/002/"},
    "T1102": {"tactic": "Command and Control", "name": "Web Service", "url": "https://attack.mitre.org/techniques/T1102/"},
    "T1087.002": {"tactic": "Discovery", "name": "Account Discovery: Domain Account", "url": "https://attack.mitre.org/techniques/T1087/002/"},
    "T1087.004": {"tactic": "Discovery", "name": "Account Discovery: Cloud Account", "url": "https://attack.mitre.org/techniques/T1087/004/"},
    "T1589.001": {"tactic": "Reconnaissance", "name": "Gather Victim Identity Information: Credentials", "url": "https://attack.mitre.org/techniques/T1589/001/"},
    "T1595": {"tactic": "Reconnaissance", "name": "Active Scanning", "url": "https://attack.mitre.org/techniques/T1595/"},
    "T1595.002": {"tactic": "Reconnaissance", "name": "Active Scanning: Vulnerability Scanning", "url": "https://attack.mitre.org/techniques/T1595/002/"},
    "T1496": {"tactic": "Impact", "name": "Resource Hijacking", "url": "https://attack.mitre.org/techniques/T1496/"},
    "T1498": {"tactic": "Impact", "name": "Network Denial of Service", "url": "https://attack.mitre.org/techniques/T1498/"},
    "T1046": {"tactic": "Discovery", "name": "Network Service Discovery", "url": "https://attack.mitre.org/techniques/T1046/"},
    "T1595.001": {"tactic": "Reconnaissance", "name": "Active Scanning: Scanning IP Blocks", "url": "https://attack.mitre.org/techniques/T1595/001/"},
    "T1110.001": {"tactic": "Credential Access", "name": "Brute Force: Password Guessing", "url": "https://attack.mitre.org/techniques/T1110/001/"},
    "T1110.003": {"tactic": "Credential Access", "name": "Brute Force: Password Spraying", "url": "https://attack.mitre.org/techniques/T1110/003/"},
    "T1021.001": {"tactic": "Lateral Movement", "name": "Remote Services: Remote Desktop Protocol", "url": "https://attack.mitre.org/techniques/T1021/001/"},
    "T1021.002": {"tactic": "Lateral Movement", "name": "Remote Services: SMB/Windows Admin Shares", "url": "https://attack.mitre.org/techniques/T1021/002/"},
    "T1021.003": {"tactic": "Lateral Movement", "name": "Remote Services: DCOM", "url": "https://attack.mitre.org/techniques/T1021/003/"},
    "T1047": {"tactic": "Execution", "name": "Windows Management Instrumentation", "url": "https://attack.mitre.org/techniques/T1047/"},
    "T1569.002": {"tactic": "Execution", "name": "System Services: Service Execution", "url": "https://attack.mitre.org/techniques/T1569/002/"},
    "T1003.002": {"tactic": "Credential Access", "name": "OS Credential Dumping: SAM", "url": "https://attack.mitre.org/techniques/T1003/002/"},
    "T1558.003": {"tactic": "Credential Access", "name": "Steal or Forge Kerberos Tickets: Kerberoasting", "url": "https://attack.mitre.org/techniques/T1558/003/"},
    "T1557": {"tactic": "Credential Access", "name": "Adversary-in-the-Middle", "url": "https://attack.mitre.org/techniques/T1557/"},
    "T1095": {"tactic": "Command and Control", "name": "Non-Application Layer Protocol", "url": "https://attack.mitre.org/techniques/T1095/"},
    "T1027": {"tactic": "Defense Evasion", "name": "Obfuscated Files or Information", "url": "https://attack.mitre.org/techniques/T1027/"},
    "T1078.001": {"tactic": "Initial Access", "name": "Valid Accounts: Default Accounts", "url": "https://attack.mitre.org/techniques/T1078/001/"},
    "T1602": {"tactic": "Collection", "name": "Data from Configuration Repository", "url": "https://attack.mitre.org/techniques/T1602/"},
}

# Severity derivation: for UNDETECTED findings, map MITRE tactic to risk severity.
TACTIC_SEVERITY = {
    "Initial Access": "Critical",
    "Execution": "Critical",
    "Persistence": "High",
    "Privilege Escalation": "High",
    "Defense Evasion": "High",
    "Credential Access": "High",
    "Command and Control": "High",
    "Exfiltration": "High",
    "Discovery": "Medium",
    "Lateral Movement": "Medium",
    "Collection": "Medium",
    "Reconnaissance": "Low",
    "Resource Development": "Low",
    "Impact": "High",
}

# CISA KEV-listed probes: auto-escalate to Critical when UNDETECTED.
KEV_PROBES = {
    "panos-cve-2024-3400-sessid", "fortios-cve-2024-21762",
    "pulse-secure-cve-2019-11510", "ivanti-cve-2024-21887",
    "citrixbleed-2-cve-2025-5777", "crushftp-cve-2024-4040-ssti",
    "gitlab-cve-2023-7028", "confluence-ognl-cve-2022-26134",
    "spring4shell-cve-2022-22965", "proxyshell-autodiscover",
}

CONFIDENCE_COLORS = {
    "high": "#28a745",
    "partial": "#fd7e14",
    "behavioral": "#17a2b8",
    "none": "#dc3545",
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}

SEVERITY_COLORS = {
    "Critical": "#dc3545",
    "High": "#fd7e14",
    "Medium": "#ffc107",
    "Low": "#17a2b8",
    "Info": "#6c757d",
}


# ============================================================================
#  custom tool: record_finding
# ============================================================================

@tool(
    "record_finding",
    "Record the result of ONE probe attempt. Call exactly once per probe, "
    "whether it succeeded, failed, or fired no detections. This writes a "
    "structured entry to the orchestrator's findings ledger which becomes "
    "the final report. Include tool_used, command_executed, mitre_id, "
    "confidence (high/partial/behavioral/none), and for UNDETECTED findings "
    "include remediation (what Suricata rule pattern would close the gap).",
    {
        "probe_name": str,
        "verdict": str,
        "fired_sids": str,
        "zeek_notices": str,
        "notes": str,
        "tool_used": str,
        "command_executed": str,
        "mitre_id": str,
        "confidence": str,
        "remediation": str,
        "zeek_signals": str,
    },
)
async def record_finding(args):
    """verdict in {DETECTED, UNDETECTED, ERROR, FP}. fired_sids/zeek_notices = CSV."""
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "probe": args.get("probe_name", ""),
        "verdict": args.get("verdict", ""),
        "fired_sids": [
            s.strip() for s in args.get("fired_sids", "").split(",") if s.strip()
        ],
        "zeek_notices": [
            s.strip() for s in args.get("zeek_notices", "").split(",") if s.strip()
        ],
        "notes": args.get("notes", ""),
        "tool_used": args.get("tool_used", ""),
        "command_executed": args.get("command_executed", ""),
        "mitre_id": args.get("mitre_id", ""),
        "confidence": args.get("confidence", ""),
        "remediation": args.get("remediation", ""),
        "zeek_signals": args.get("zeek_signals", ""),
    }
    if _ledger_path:
        with open(_ledger_path, "a") as f:
            f.write(json.dumps(entry) + "\n")
    return {
        "content": [
            {
                "type": "text",
                "text": f"recorded: {entry['probe']} -> {entry['verdict']} "
                f"(sids={len(entry['fired_sids'])}, "
                f"notices={len(entry['zeek_notices'])})",
            }
        ]
    }


# ============================================================================
#  system prompt
# ============================================================================

SYSTEM_PROMPT = """\
You are a purple-team defensive-evaluation agent operating on an AUTHORIZED lab
network owned by the user (their own AWS account, their own Suricata+Zeek
sensor, their own probe targets).

## Mission

Run probe candidates from the attacker box against the victim IP, observe what
Suricata + Zeek detect via sensor logs, and classify each probe:

  - DETECTED   = a relevant Suricata SID fired (regardless of whether it's already in the CI catalog)
  - UNDETECTED = probe reached the wire but NO rule matched (rule-engineering opportunity)
  - ERROR      = probe failed to run (tool missing, connection refused, etc.)
  - FP         = SID fired but is clearly unrelated to the probe technique (false positive)

## Lab endpoints

- Attacker: ssh {ssh_opts} kali@{attacker_ip}    -- run probes FROM here (Kali Linux; user is 'kali')
- Sensor:   ssh {ssh_opts} ubuntu@{sensor_ip}    -- READ logs here (Ubuntu; read-only)
- Victim:   {victim_ip}                          -- TARGET IP (no SSH from you)

SSH options string (use verbatim):
  -i {key_path} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5

## Noise floor (IGNORE these background SIDs)

These SIDs fire on nearly every probe due to ambient lab traffic. Do NOT count
them toward DETECTED or include in fired_sids unless they are the ONLY SID and
directly relevant to the probe's technique:
  - 9000003 (TCP SYN-scan canary)
  - 2001219 (ET SCAN Potential SSH Scan)

## Probe pool

A curated probe pool lives at: {probes_file}
Start by reading it with the Read tool. Each entry has: name, category,
mitre (ATT&CK technique ID), rationale, expected_sids (if known), and a
`command` (bash) to run on the attacker.

You may pick probes from the pool or improvise variants. PREFER the pool --
those commands are validated to reach the wire. You may skip probes marked
`already_in_catalog: true` in the pool since running them only re-confirms
existing coverage. Prioritize probes marked `expected_verdict: UNDETECTED`
and novel techniques not yet covered.

When the probe pool has `requires` fields, attempt prerequisite probes first.
When a probe `produces` facts, note them -- subsequent probes that `require`
those facts should be prioritized next.

## Per-probe iteration loop

IMPORTANT: Minimize SSH calls. Use compound commands to batch work into fewer
tool invocations. Each SSH call reuses connections (ControlMaster) but each
Bash tool call is still a turn.

For each probe you attempt:

1. BASELINE + PROBE (one or two Bash calls):
   Option A (two calls, simpler):
     BEFORE=$(ssh <sensor> "sudo wc -l /var/log/suricata/eve.json | awk '{{print \\$1}}'")
     ssh <attacker> "<probe command>"
   Option B (one call, faster -- preferred when the probe is a simple one-liner):
     BEFORE=$(ssh <sensor> "sudo wc -l /var/log/suricata/eve.json | awk '{{print \\$1}}'"); \\
     ssh <attacker> "<probe command>"; echo "BEFORE=$BEFORE"
   Use --max-time 5 on curl and `timeout N` on nc/long-runners.

2. CHECK (ONE compound SSH call to sensor -- do NOT split into separate calls):
     ssh <sensor> "
       echo '=== ALERTS ===';
       sudo tail -n +\\$((BEFORE + 1)) /var/log/suricata/eve.json 2>/dev/null \\
         | jq -c 'if .event_type == \\"alert\\" then {{type:\\"alert\\", sid:.alert.signature_id, sig:.alert.signature}}
                   elif .event_type == \\"anomaly\\" then {{type:\\"anomaly\\", layer:.anomaly.layer, event:.anomaly.event}}
                   elif .event_type == \\"tls\\" then {{type:\\"tls\\", sni:.tls.sni, ja3:.tls.ja3.hash}}
                   else empty end' | sort -u | head -30;
       echo '=== ZEEK-NOTICES ===';
       sudo tail -c 10000 /opt/zeek/logs/current/notice.log 2>/dev/null \\
         | jq -rc '.note' 2>/dev/null | sort -u | tail -10;
       echo '=== ZEEK-SSH ===';
       sudo tail -c 5000 /opt/zeek/logs/current/ssh.log 2>/dev/null \\
         | jq -rc '{{client, hassh}}' 2>/dev/null | tail -5;
       echo '=== ZEEK-TLS ===';
       sudo tail -c 5000 /opt/zeek/logs/current/ssl.log 2>/dev/null \\
         | jq -rc '{{server_name, ja3}}' 2>/dev/null | tail -5;
       echo '=== ZEEK-DNS ===';
       sudo tail -c 5000 /opt/zeek/logs/current/dns.log 2>/dev/null \\
         | jq -rc '{{query, qtype_name, rcode_name}}' 2>/dev/null | tail -10
     "
   This single SSH call gives you alerts, anomalies, TLS SNI, and all relevant
   Zeek protocol logs. Anomalies and Zeek entries count as detection signals
   even without a Suricata alert ("behavioral" confidence).
   You may omit Zeek sections not relevant to the probe type to keep output short.

5. CLASSIFY -- call the `record_finding` tool with:
     - probe_name        -- the pool entry's `name` (or a descriptive name if improvised)
     - verdict           -- DETECTED / UNDETECTED / ERROR / FP
     - fired_sids        -- CSV of SIDs from step 3 (e.g. "2047929,2024792").
                            Exclude noise-floor SIDs (9000003, 2001219) unless they
                            are the only relevant SID.
     - zeek_notices      -- CSV of Zeek notice types if novel
     - notes             -- one-line rationale. Mention any anomalies or Zeek
                            protocol-log signals observed even if no alert fired.
     - tool_used         -- primary tool (curl, nmap, impacket, nc, hydra, dig,
                            hping3, smbclient, flightsim, python3, nuclei, nikto)
     - command_executed  -- the exact bash command you ran in step 2
     - mitre_id          -- ATT&CK technique ID (from pool entry's `mitre` field,
                            or your best match for improvised probes)
     - confidence        -- detection confidence level:
                            "high" = specific signature matched (ET TROJAN, exact CVE SID)
                            "partial" = generic/heuristic rule caught it (decoder SID, HUNTING rule)
                            "behavioral" = Zeek-only signal, anomaly, or protocol-log evidence
                            "none" = true gap, no signal at any layer
     - remediation       -- for UNDETECTED/FP findings ONLY: suggest what Suricata rule
                            pattern would close this gap (e.g., "http.uri content
                            match for /global-protect/portal/ + Cookie SESSID
                            path-traversal" or "tls.sni match for api.openai.com")
     - zeek_signals      -- what Zeek observed for this probe. Summarize protocol
                            log evidence: TLS SNI + JA3 from ssl.log, SSH client
                            banner + HASSH from ssh.log, DNS queries + rcodes from
                            dns.log, conn.log metadata (protocol, bytes, duration).
                            Example: "ssl.log: sni=api.openai.com ja3=abc123 |
                            conn.log: proto=tcp bytes=1420 duration=0.3s"
                            This is IMPORTANT -- even when Suricata has no alert,
                            Zeek protocol metadata proves traffic visibility and
                            enables behavioral detection.

## Adaptive strategy

After every 10 probes, re-read your findings ledger at: {ledger_path}
Use it to adapt your strategy:
  - If 3+ probes in a category are UNDETECTED, note the pattern and move to a different category
  - If a probe is DETECTED, try an EVASION VARIANT: different encoding,
    port, User-Agent, or protocol wrapper. Record it with "-evasion" suffix.
  - If a probe is UNDETECTED, try the same technique with a different tool to confirm
    the gap isn't tool-specific (e.g., curl vs nc vs python3)
  - Prioritize CISA KEV CVEs and active-exploitation techniques over theoretical attacks

## Rules of engagement (HARD CONSTRAINTS)

- NO `rm`, `shutdown`, `reboot`, `iptables`, `systemctl stop/disable`,
  `aws ec2 terminate-instances`, or any command that mutates the lab state.
- NO SSH or network connection to ANY IP other than the attacker, sensor,
  or victim listed above.
- NO git operations, wiki edits, or code commits.
- NO running the full `run_attacks.sh` battery -- that's CI's job. Run
  probes ONE at a time.
- If a probe hangs for >10s, move on. Do NOT retry more than once.
- Call `record_finding` for EVERY probe attempted, including errors.
- Do not attempt to modify any file on the lab sensor or victim.

## Existing CI coverage (do NOT re-exercise unless for comparison)

The catalog already covers these -- running them will still produce a DETECTED verdict,
but they add no new signal:
  - DoH tunneling (Cloudflare, Google, Quad9)
  - Impacket AD chain (GetNPUsers/GetUserSPNs/secretsdump/lookupsid)
  - TeamCity CVE-2024-27198 / ScreenConnect CVE-2024-1709
  - HTTP/2 h2c prior-knowledge + CL.0 smuggling
  - SaaS SNI exfil (Telegram/Dropbox/webhook.site/pipedream/ngrok/trycloudflare/serveo/pythonhosted)
  - cryptominer-live (supportxmr SNI + XMRig stratum login)
  - Existing run_attacks.sh battery (nmap/hydra/nikto/lateral-smb/nuclei/flightsim)

Focus your budget on NOVEL probes that extend coverage, OR on probes the pool
marks with `expected_verdict: UNDETECTED` -- exercising known gaps is useful because
the sensor-side proof that no detection fires is itself the deliverable.

## Termination

When you've either (a) worked through the pool, or (b) hit the turn budget,
or (c) exhausted novel candidates -- reply with the literal phrase
"PURPLE RUN COMPLETE" and stop calling tools. The orchestrator will gather
your findings and write the final report.

Your budget: {max_turns} turns. Pace yourself -- each probe iteration should
use 2-3 turns (baseline+probe, check, classify). Batching commands into fewer
Bash calls is critical for throughput.
"""


# ============================================================================
#  runner
# ============================================================================

async def run_agent(args):
    global _ledger_path

    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    _ledger_path = REPORTS_DIR / f"findings-{ts}.jsonl"
    _ledger_path.touch()

    probes_src = Path(args.probe_pool).resolve() if args.probe_pool else (SCRIPT_DIR / "probes.yaml")
    if not probes_src.exists():
        print(f"probe pool not found: {probes_src}", file=sys.stderr)
        sys.exit(1)

    # Pre-substitute {{VICTIM_IP}} in the probe pool so the agent can't forget.
    # Write the staged copy next to the ledger.
    probes_path = REPORTS_DIR / f"probes-staged-{ts}.yaml"
    probes_raw = probes_src.read_text(encoding="utf-8")
    probes_path.write_text(
        probes_raw.replace("{{VICTIM_IP}}", args.victim_ip),
        encoding="utf-8",
    )

    key_path = args.key

    ssh_opts = (
        f"-i {key_path} "
        f"-o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null "
        f"-o ConnectTimeout=5 "
        f"-o ControlMaster=auto "
        f"-o ControlPath=/tmp/purple-ssh-%r@%h:%p "
        f"-o ControlPersist=300"
    )

    system_prompt = SYSTEM_PROMPT.format(
        attacker_ip=args.attacker_ip,
        sensor_ip=args.sensor_ip,
        victim_ip=args.victim_ip,
        key_path=key_path,
        ssh_opts=ssh_opts,
        probes_file=str(probes_path),
        ledger_path=str(_ledger_path),
        max_turns=args.budget,
    )

    findings_server = create_sdk_mcp_server(
        name="purple-findings",
        version="1.0.0",
        tools=[record_finding],
    )

    options = ClaudeAgentOptions(
        system_prompt=system_prompt,
        max_turns=args.budget,
        allowed_tools=[
            "Bash",
            "Read",
            "mcp__purple-findings__record_finding",
        ],
        mcp_servers={"purple-findings": findings_server},
        permission_mode="bypassPermissions",
    )

    kickoff = (
        "Begin the purple-team run. First, use the Read tool to read the probe "
        "pool at the path given in your system prompt. Then iterate through "
        "candidates (baseline -> probe -> check -> record_finding) until you hit "
        "the turn budget or have nothing novel left to try. Focus on probes "
        "NOT already covered by the CI catalog. Call record_finding for every "
        "attempt. Say 'PURPLE RUN COMPLETE' when you're done."
    )

    print(f"[purple-agent] starting run {ts}")
    print(f"[purple-agent] ledger:  {_ledger_path}")
    print(f"[purple-agent] budget:  {args.budget} turns")
    print(f"[purple-agent] lab:     atk={args.attacker_ip} sns={args.sensor_ip} vic={args.victim_ip}")
    print("=" * 72)

    turn = 0
    try:
        async with ClaudeSDKClient(options=options) as client:
            await client.query(kickoff)
            async for message in client.receive_response():
                if isinstance(message, AssistantMessage):
                    turn += 1
                    for block in message.content:
                        if isinstance(block, TextBlock):
                            text = block.text.strip()
                            if text:
                                preview = text[:160].replace("\n", " ")
                                print(f"[turn {turn:>2}] {preview}")
                        elif isinstance(block, ToolUseBlock):
                            inp_preview = str(block.input)[:120].replace("\n", " ")
                            print(f"[turn {turn:>2}] -> {block.name}({inp_preview}...)")
    except KeyboardInterrupt:
        print("\n[purple-agent] interrupted -- writing partial report")
    except Exception as e:
        print(f"\n[purple-agent] error: {type(e).__name__}: {e}")

    print("=" * 72)
    write_html_report(REPORTS_DIR, ts, _ledger_path, args, probes_yaml_path=probes_path)


# ============================================================================
#  report writer — HTML
# ============================================================================

def _load_findings(ledger_path):
    findings = []
    if not ledger_path.exists():
        return findings
    with open(ledger_path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return findings


def _load_probes_yaml(probes_yaml_path):
    """Load probes.yaml into a dict keyed by probe name for fallback enrichment."""
    if not probes_yaml_path or not probes_yaml_path.exists():
        return {}
    try:
        import yaml
        with open(probes_yaml_path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
        return {p["name"]: p for p in data.get("probes", []) if "name" in p}
    except Exception:
        return {}


def _infer_tool(command):
    """Best-effort tool inference from a command string."""
    if not command:
        return ""
    patterns = [
        (r'\bcurl\b', "curl"),
        (r'\bnmap\b', "nmap"),
        (r'\bnc\b', "nc"),
        (r'\bimpacket-', "impacket"),
        (r'\bflightsim\b', "flightsim"),
        (r'\bpython3?\b', "python3"),
        (r'\bhydra\b', "hydra"),
        (r'\bnikto\b', "nikto"),
        (r'\bnuclei\b', "nuclei"),
        (r'\bsqlmap\b', "sqlmap"),
        (r'\bprintf\b.*\bnc\b', "nc"),
    ]
    for pat, tool_name in patterns:
        if re.search(pat, command):
            return tool_name
    return "bash"


def _normalize_verdict(raw):
    """Map legacy verdicts (PROMOTE/SKIP/GAP/FP) onto the current 3-state taxonomy.

    Returns (verdict, fp_flag). fp_flag=True preserves the 'false positive' nuance
    for FP findings (the technique wasn't really detected — an unrelated SID fired).
    """
    v = (raw or "").upper()
    if v in ("DETECTED", "PROMOTE", "SKIP"):
        return "DETECTED", False
    if v == "UNDETECTED" or v == "GAP":
        return "UNDETECTED", False
    if v == "FP":
        return "UNDETECTED", True
    if v == "ERROR":
        return "ERROR", False
    return v, False


def _enrich_findings(findings, probes_yaml_path):
    """Enrich findings with MITRE details, severity, and fallback data from probes.yaml."""
    pool = _load_probes_yaml(probes_yaml_path)
    enriched = []

    for f in findings:
        e = dict(f)
        probe_name = e.get("probe", "")
        pool_entry = pool.get(probe_name, {})

        # Normalize verdict (backward-compat with PROMOTE/SKIP/GAP/FP ledgers)
        verdict, fp_flag = _normalize_verdict(e.get("verdict", ""))
        e["verdict"] = verdict
        e["fp"] = fp_flag

        # MITRE ID: prefer finding, fallback to pool
        mitre_id = e.get("mitre_id", "") or pool_entry.get("mitre", "")
        e["mitre_id"] = mitre_id

        # Resolve MITRE details from lookup
        mitre_info = MITRE_LOOKUP.get(mitre_id, {})
        e["mitre_tactic"] = mitre_info.get("tactic", "")
        e["mitre_name"] = mitre_info.get("name", "")
        e["mitre_url"] = mitre_info.get("url", "")

        # Tool: prefer finding, fallback to inference from command
        cmd = e.get("command_executed", "") or pool_entry.get("command", "")
        e["command_executed"] = cmd
        e["tool_used"] = e.get("tool_used", "") or _infer_tool(cmd)

        # Category from pool
        e["category"] = pool_entry.get("category", "")

        # Confidence: prefer finding, fallback to inference
        confidence = e.get("confidence", "")
        if not confidence:
            if verdict == "DETECTED" and not fp_flag:
                confidence = "high"
            else:
                confidence = "none"
        e["confidence"] = confidence

        # Remediation and Zeek signals: pass through from finding
        e["remediation"] = e.get("remediation", "")
        e["zeek_signals"] = e.get("zeek_signals", "")

        # KEV flag
        e["kev"] = probe_name in KEV_PROBES

        # Severity: deterministic from verdict + tactic, KEV override.
        # FP is treated like ERROR (sensor fired on wrong thing — low severity noise).
        if verdict == "UNDETECTED" and not fp_flag:
            if e["kev"]:
                e["severity"] = "Critical"
            else:
                tactic = e["mitre_tactic"]
                e["severity"] = TACTIC_SEVERITY.get(tactic, "Medium")
        elif verdict == "ERROR" or fp_flag:
            e["severity"] = "Low"
        else:
            e["severity"] = "Info"

        enriched.append(e)

    # Sort by severity then probe name
    enriched.sort(key=lambda x: (SEVERITY_ORDER.get(x["severity"], 99), x.get("probe", "")))
    return enriched


def _esc(text):
    """HTML-escape a string."""
    return html_mod.escape(str(text)) if text else ""


def _build_css():
    return """
    * { margin: 0; padding: 0; box-sizing: border-box; }
    body {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, "Helvetica Neue", Arial, sans-serif;
        line-height: 1.6; color: #212529; background: #f8f9fa;
        max-width: 1100px; margin: 0 auto; padding: 20px;
    }
    h1 { font-size: 1.8rem; margin-bottom: 0.3rem; color: #1a1a2e; }
    h2 { font-size: 1.4rem; margin: 2rem 0 1rem; color: #1a1a2e; border-bottom: 2px solid #dee2e6; padding-bottom: 0.3rem; }
    h3 { font-size: 1.1rem; margin: 1rem 0 0.5rem; }
    .cover { background: #1a1a2e; color: #fff; padding: 2rem; border-radius: 8px; margin-bottom: 2rem; }
    .cover h1 { color: #fff; font-size: 2rem; }
    .cover .meta { color: #a0a0c0; margin-top: 0.5rem; font-size: 0.9rem; }
    .cover .meta span { margin-right: 2rem; }
    .stat-boxes { display: flex; gap: 1rem; margin: 1.5rem 0; flex-wrap: wrap; }
    .stat-box {
        flex: 1; min-width: 140px; padding: 1.2rem; border-radius: 8px;
        text-align: center; color: #fff;
    }
    .stat-box .num { font-size: 2.2rem; font-weight: 700; }
    .stat-box .label { font-size: 0.8rem; text-transform: uppercase; letter-spacing: 0.05em; opacity: 0.9; }
    .stat-promote { background: #28a745; }
    .stat-gap { background: #dc3545; }
    .stat-skip { background: #6c757d; }
    .stat-error { background: #ffc107; color: #212529; }
    .summary-text { background: #fff; padding: 1.2rem; border-radius: 8px; border: 1px solid #dee2e6; margin: 1rem 0; }
    .detection-rates { display: flex; gap: 2rem; margin: 1rem 0; }
    .rate-item { text-align: center; }
    .rate-item .pct { font-size: 2rem; font-weight: 700; }
    .rate-item .rlabel { font-size: 0.8rem; color: #666; }

    /* MITRE matrix */
    .mitre-matrix { width: 100%; border-collapse: collapse; margin: 1rem 0; font-size: 0.85rem; }
    .mitre-matrix th { background: #1a1a2e; color: #fff; padding: 0.5rem; text-align: left; }
    .mitre-matrix td { padding: 0.4rem 0.5rem; border: 1px solid #dee2e6; vertical-align: top; }
    .mitre-badge {
        display: inline-block; padding: 2px 8px; border-radius: 4px;
        font-size: 0.75rem; margin: 2px; color: #fff; white-space: nowrap;
    }
    .mitre-detected { background: #28a745; }
    .mitre-gap { background: #dc3545; }
    .mitre-error { background: #ffc107; color: #212529; }

    /* Finding cards */
    .finding-card {
        background: #fff; border: 1px solid #dee2e6; border-radius: 8px;
        margin: 1rem 0; overflow: hidden;
    }
    .finding-header {
        padding: 0.8rem 1rem; display: flex; align-items: center; gap: 0.8rem; flex-wrap: wrap;
    }
    .finding-body { padding: 1rem; border-top: 1px solid #eee; }
    .badge {
        display: inline-block; padding: 3px 10px; border-radius: 4px;
        font-size: 0.75rem; font-weight: 600; color: #fff;
    }
    .badge-detected { background: #28a745; }
    .badge-undetected { background: #dc3545; }
    .badge-error { background: #ffc107; color: #212529; }
    .badge-fp { background: #e83e8c; }
    .badge-skip { background: #6c757d; }
    .badge-severity { border: 2px solid; background: transparent; }
    .finding-title { font-weight: 600; font-size: 1rem; }
    .mitre-link { font-size: 0.8rem; color: #0d6efd; text-decoration: none; }
    .mitre-link:hover { text-decoration: underline; }
    .field-label { font-weight: 600; color: #495057; font-size: 0.85rem; display: block; margin-top: 0.8rem; }
    .field-label:first-child { margin-top: 0; }
    pre.cmd {
        background: #1e1e1e; color: #d4d4d4; padding: 0.8rem; border-radius: 6px;
        overflow-x: auto; font-size: 0.8rem; line-height: 1.5; margin-top: 0.3rem;
        white-space: pre-wrap; word-break: break-all;
    }
    .detection-yes { color: #28a745; font-weight: 600; }
    .detection-no { color: #dc3545; font-weight: 600; }
    .sid-list { font-family: monospace; font-size: 0.85rem; color: #495057; }
    .notes-text { color: #495057; margin-top: 0.3rem; }
    .ts-text { font-size: 0.75rem; color: #999; margin-top: 0.5rem; }

    /* Gap analysis table */
    .gap-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin: 1rem 0; }
    .gap-table th { background: #dc3545; color: #fff; padding: 0.5rem; text-align: left; }
    .gap-table td { padding: 0.5rem; border: 1px solid #dee2e6; vertical-align: top; }
    .gap-table tr:nth-child(even) { background: #fff5f5; }

    /* Promote table */
    .promote-table { width: 100%; border-collapse: collapse; font-size: 0.85rem; margin: 1rem 0; }
    .promote-table th { background: #28a745; color: #fff; padding: 0.5rem; text-align: left; }
    .promote-table td { padding: 0.5rem; border: 1px solid #dee2e6; vertical-align: top; }
    .promote-table tr:nth-child(even) { background: #f0fff0; }

    details { margin: 1rem 0; }
    summary { cursor: pointer; font-weight: 600; color: #0d6efd; }

    .severity-def { display: flex; gap: 1rem; flex-wrap: wrap; margin: 0.5rem 0; }
    .severity-def .sd-item { flex: 1; min-width: 200px; padding: 0.5rem; border-radius: 6px; border-left: 4px solid; background: #fff; }

    @media print {
        body { background: #fff; padding: 0; }
        .cover { break-after: page; }
        .finding-card { break-inside: avoid; }
        h2 { break-after: avoid; }
    }
"""


def _build_cover(ts, args):
    dt = datetime.strptime(ts, "%Y%m%dT%H%M%SZ").strftime("%B %d, %Y %H:%M UTC")
    return f"""
    <div class="cover">
        <h1>Purple-Team Defensive Evaluation Report</h1>
        <p style="font-size:1.1rem; color:#c0c0e0; margin-top:0.5rem;">
            Automated Suricata + Zeek Detection Coverage Assessment
        </p>
        <div class="meta">
            <span>Date: {_esc(dt)}</span>
            <span>Assessor: Automated (Claude Agent)</span>
        </div>
        <div class="meta" style="margin-top:0.3rem;">
            <span>Attacker: {_esc(args.attacker_ip)}</span>
            <span>Sensor: {_esc(args.sensor_ip)}</span>
            <span>Victim: {_esc(args.victim_ip)}</span>
        </div>
        <div class="meta" style="margin-top:0.3rem;">
            <span>Turn Budget: {args.budget}</span>
            <span>Run ID: {_esc(ts)}</span>
        </div>
    </div>
"""


def _classify_by_layer(enriched):
    """Classify each finding into one of four detection states.

    Returns (suricata_alert, zeek_alert_only, visibility_only, no_visibility):
      - suricata_alert    : fired_sids present (Suricata signature matched)
      - zeek_alert_only   : no Suricata SID, but Zeek notice.log or confidence=behavioral
      - visibility_only   : no alert either side, but Zeek protocol logs captured the traffic
      - no_visibility     : nothing — the sensor didn't observe the probe at all
    """
    suricata_alert, zeek_alert_only, visibility_only, no_visibility = [], [], [], []
    for f in enriched:
        has_suricata = bool(f.get("fired_sids"))
        has_zeek_alert = bool(f.get("zeek_notices")) or f.get("confidence") == "behavioral"
        has_zeek_visibility = bool(f.get("zeek_signals"))
        if has_suricata:
            suricata_alert.append(f)
        elif has_zeek_alert:
            zeek_alert_only.append(f)
        elif has_zeek_visibility:
            visibility_only.append(f)
        else:
            no_visibility.append(f)
    return suricata_alert, zeek_alert_only, visibility_only, no_visibility


def _build_exec_summary(enriched, buckets):
    total = len(enriched)
    n_error = len(buckets.get("ERROR", []))
    n_fp = sum(1 for f in enriched if f.get("fp"))

    suricata_alert, zeek_alert_only, visibility_only, no_visibility = _classify_by_layer(enriched)
    n_suri = len(suricata_alert)
    n_zeek = len(zeek_alert_only)
    n_vis = len(visibility_only)
    n_blind = len(no_visibility)
    n_undetected = n_vis + n_blind

    suri_pct = f"{100 * n_suri / total:.0f}" if total > 0 else "0"
    any_detect_pct = f"{100 * (n_suri + n_zeek) / total:.0f}" if total > 0 else "0"
    undetected_pct = f"{100 * n_undetected / total:.0f}" if total > 0 else "0"

    # Count unique SIDs fired
    unique_sids = set()
    for f in suricata_alert:
        for sid in f.get("fired_sids", []):
            unique_sids.add(sid)

    # Undetected breakdown by tactic (visibility_only + no_visibility — neither layer alerted)
    undetected = visibility_only + no_visibility
    gap_tactics = {}
    for f in undetected:
        t = f.get("mitre_tactic", "Unknown")
        gap_tactics[t] = gap_tactics.get(t, 0) + 1
    top_gap_tactic = max(gap_tactics, key=gap_tactics.get) if gap_tactics else "N/A"

    crit_gaps = sum(1 for f in undetected if f.get("severity") == "Critical")
    high_gaps = sum(1 for f in undetected if f.get("severity") == "High")
    kev_gaps = sum(1 for f in undetected if f.get("kev"))

    all_tactics = set()
    gap_tactic_set = set()
    for f in enriched:
        t = f.get("mitre_tactic", "")
        if t:
            all_tactics.add(t)
    for f in undetected:
        t = f.get("mitre_tactic", "")
        if t:
            gap_tactic_set.add(t)
    tactics_tested = len(all_tactics)
    tactics_with_gaps = len(gap_tactic_set)

    tools = set(f.get("tool_used", "") for f in enriched if f.get("tool_used"))

    narrative = (
        f"This assessment executed <strong>{total} attack simulations</strong> across "
        f"{tactics_tested} MITRE ATT&amp;CK tactics using {len(tools)} distinct tools "
        f"({', '.join(sorted(tools)[:6])}{', ...' if len(tools) > 6 else ''}). "
    )
    narrative += (
        f"<strong>Suricata signatures fired on {n_suri} attacks ({suri_pct}%)</strong>, "
        f"matching {len(unique_sids)} unique SID{'s' if len(unique_sids) != 1 else ''}. "
    )
    if n_zeek > 0:
        narrative += (
            f"<strong>Zeek notices fired on {n_zeek} additional attacks</strong> "
            f"(notice.log / behavioral signals with no Suricata signature). "
        )
    narrative += (
        f"<strong>{n_undetected} attacks ({undetected_pct}%) produced no alert on either layer</strong> -- "
        f"detection gaps requiring rule-engineering work. "
    )
    if n_vis > 0:
        narrative += (
            f"Of those, <strong>{n_vis} were visible in Zeek protocol logs</strong> "
            f"(TLS SNI / JA3 / HTTP / DNS / conn-log metadata) -- actionable leads for writing "
            f"Suricata rules informed by Zeek evidence. "
        )
    if n_blind > 0:
        narrative += (
            f"<strong>{n_blind} attacks produced no sensor evidence at all</strong> -- true blind spots. "
        )
    if crit_gaps > 0:
        narrative += (
            f"<strong>{crit_gaps} gaps are rated Critical</strong> -- undetected initial-access "
            f"or code-execution attacks that would allow an adversary to establish a foothold. "
        )
    if high_gaps > 0:
        narrative += (
            f"<strong>{high_gaps} gaps are rated High</strong> -- undetected command-and-control, "
            f"credential theft, or data exfiltration activity. "
        )
    if kev_gaps > 0:
        narrative += (
            f"<strong>{kev_gaps} undetected attacks target CISA Known Exploited Vulnerabilities</strong>, "
            f"indicating active real-world exploitation with no sensor coverage. "
        )
    if gap_tactics:
        narrative += (
            f"The highest concentration of gaps is in the "
            f"<strong>{_esc(top_gap_tactic)}</strong> tactic ({gap_tactics[top_gap_tactic]} gaps)."
        )

    footer_notes = []
    if n_error > 0:
        footer_notes.append(f"{n_error} attacks failed to execute (tool missing, timeout, connection refused)")
    if n_fp > 0:
        footer_notes.append(f"{n_fp} detections were false positives (unrelated signature fired)")
    footer_html = ""
    if footer_notes:
        footer_html = '<p style="font-size:0.85rem; color:#666; margin-top:0.8rem;">' + ". ".join(footer_notes) + ".</p>"

    return f"""
    <h2>Executive Summary</h2>
    <div class="stat-boxes">
        <div class="stat-box" style="background:#1a1a2e;"><div class="num">{total}</div><div class="label">Attacks Conducted</div></div>
        <div class="stat-box stat-promote"><div class="num">{n_suri}</div><div class="label">Suricata Alerts</div></div>
        <div class="stat-box" style="background:#17a2b8;"><div class="num">{n_zeek}</div><div class="label">Zeek Alerts</div></div>
        <div class="stat-box stat-gap"><div class="num">{n_undetected}</div><div class="label">No Detection</div></div>
    </div>
    <div class="detection-rates">
        <div class="rate-item">
            <div class="pct" style="color:#28a745;">{suri_pct}%</div>
            <div class="rlabel">Suricata Detection Rate</div>
        </div>
        <div class="rate-item">
            <div class="pct" style="color:#28a745;">{any_detect_pct}%</div>
            <div class="rlabel">Any-Layer Detection Rate</div>
        </div>
        <div class="rate-item">
            <div class="pct">{tactics_tested}</div>
            <div class="rlabel">ATT&amp;CK Tactics Tested</div>
        </div>
        <div class="rate-item">
            <div class="pct" style="color:#dc3545;">{tactics_with_gaps}</div>
            <div class="rlabel">Tactics with Gaps</div>
        </div>
    </div>
    <div class="summary-text"><p>{narrative}</p>{footer_html}</div>
"""


def _build_suricata_alerts(enriched):
    """Build a prominent table of every probe that triggered Suricata SIDs."""
    fired = [f for f in enriched if f.get("fired_sids")]
    if not fired:
        return (
            '<h2>Suricata Alerts Fired</h2>'
            '<p style="color:#dc3545; font-weight:600;">No Suricata signatures fired during this run. '
            'Every probe either triggered Zeek-only signals or produced no detection at all.</p>'
        )

    unique_sids = set()
    for f in fired:
        for sid in f.get("fired_sids", []):
            unique_sids.add(sid)

    parts = [
        '<h2>Suricata Alerts Fired</h2>',
        f'<p><strong>{len(fired)}</strong> of <strong>{len(enriched)}</strong> probes triggered '
        f'<strong>{len(unique_sids)}</strong> unique Suricata signature'
        f'{"s" if len(unique_sids) != 1 else ""}.</p>',
        '<table class="gap-table" style="border-left:3px solid #28a745;">'
        '<thead><tr style="background:#28a745;">'
        '<th>Probe</th><th>SIDs Fired</th><th>MITRE</th><th>Tool</th>'
        '</tr></thead><tbody>',
    ]

    fired_sorted = sorted(fired, key=lambda f: f.get("probe", ""))
    for f in fired_sorted:
        sids = ", ".join(f.get("fired_sids", []))
        parts.append(
            f'<tr>'
            f'<td><strong>{_esc(f.get("probe", ""))}</strong></td>'
            f'<td style="font-family:monospace;">{_esc(sids)}</td>'
            f'<td>{_esc(f.get("mitre_id", ""))}</td>'
            f'<td><code>{_esc(f.get("tool_used", ""))}</code></td>'
            f'</tr>'
        )
    parts.append('</tbody></table>')
    return "\n".join(parts)


def _build_mitre_matrix(enriched):
    # Group by tactic -> list of (technique_id, technique_name, verdict)
    tactic_map = {}
    for f in enriched:
        tactic = f.get("mitre_tactic") or "Unknown"
        tid = f.get("mitre_id") or "?"
        tname = f.get("mitre_name") or tid
        verdict = f.get("verdict", "").upper()
        probe = f.get("probe", "")
        key = (tactic, tid, tname)
        if key not in tactic_map:
            tactic_map[key] = []
        tactic_map[key].append((verdict, probe))

    # Order tactics by ATT&CK kill chain
    tactic_order = [
        "Reconnaissance", "Resource Development", "Initial Access", "Execution",
        "Persistence", "Privilege Escalation", "Defense Evasion", "Credential Access",
        "Discovery", "Lateral Movement", "Collection", "Command and Control",
        "Exfiltration", "Impact", "Unknown",
    ]

    rows_by_tactic = {}
    for (tactic, tid, tname), probes in tactic_map.items():
        if tactic not in rows_by_tactic:
            rows_by_tactic[tactic] = []
        # Determine overall status: if any probe for this technique is UNDETECTED, mark red
        verdicts = [v for v, _ in probes]
        if "UNDETECTED" in verdicts:
            css_class = "mitre-gap"
        elif "ERROR" in verdicts:
            css_class = "mitre-error"
        else:
            css_class = "mitre-detected"
        probe_names = ", ".join(p for _, p in probes)
        rows_by_tactic[tactic].append((tid, tname, css_class, probe_names))

    html_parts = ['<h2>MITRE ATT&amp;CK Coverage Matrix</h2>']
    html_parts.append('<table class="mitre-matrix"><thead><tr><th>Tactic</th><th>Techniques</th></tr></thead><tbody>')

    for tactic in tactic_order:
        if tactic not in rows_by_tactic:
            continue
        badges = []
        for tid, tname, css_class, probe_names in sorted(rows_by_tactic[tactic]):
            badges.append(
                f'<span class="mitre-badge {css_class}" title="{_esc(tname)}: {_esc(probe_names)}">{_esc(tid)}</span>'
            )
        html_parts.append(f'<tr><td><strong>{_esc(tactic)}</strong></td><td>{"".join(badges)}</td></tr>')

    html_parts.append('</tbody></table>')
    html_parts.append('<p style="font-size:0.8rem; color:#666;">Green = detected, Red = gap, Yellow = error. Hover for details.</p>')
    return "\n".join(html_parts)


def _build_finding_card(f):
    verdict = f.get("verdict", "").upper()
    badge_class = f"badge-{verdict.lower()}" if verdict in ("DETECTED", "UNDETECTED", "ERROR") else "badge-skip"
    if f.get("fp"):
        badge_class = "badge-fp"
    severity = f.get("severity", "Info")
    sev_color = SEVERITY_COLORS.get(severity, "#6c757d")

    # Confidence + KEV badges
    confidence = f.get("confidence", "")
    conf_color = CONFIDENCE_COLORS.get(confidence, "#6c757d")
    kev_badge = ' <span class="badge" style="background:#7b2d8e;">CISA KEV</span>' if f.get("kev") else ""

    # Header
    header = f"""
    <div class="finding-header" style="border-left: 5px solid {sev_color};">
        <span class="badge {badge_class}">{_esc(verdict)}</span>
        <span class="badge badge-severity" style="border-color:{sev_color}; color:{sev_color};">{_esc(severity)}</span>
        <span class="badge" style="background:{conf_color};" title="Detection confidence">{_esc(confidence or 'unknown')}</span>{kev_badge}
        <span class="finding-title">{_esc(f.get('probe', '(unnamed)'))}</span>
    </div>
    """

    # Body
    body_parts = []

    # MITRE mapping
    mitre_id = f.get("mitre_id", "")
    mitre_name = f.get("mitre_name", "")
    mitre_url = f.get("mitre_url", "")
    mitre_tactic = f.get("mitre_tactic", "")
    if mitre_id:
        mitre_str = f'{_esc(mitre_id)} - {_esc(mitre_name)}'
        if mitre_tactic:
            mitre_str += f' ({_esc(mitre_tactic)})'
        if mitre_url:
            body_parts.append(f'<span class="field-label">MITRE ATT&amp;CK</span><a class="mitre-link" href="{_esc(mitre_url)}" target="_blank">{mitre_str}</a>')
        else:
            body_parts.append(f'<span class="field-label">MITRE ATT&amp;CK</span><span>{mitre_str}</span>')

    # Tool
    tool_used = f.get("tool_used", "")
    if tool_used:
        body_parts.append(f'<span class="field-label">Tool</span><code>{_esc(tool_used)}</code>')

    # Command
    cmd = f.get("command_executed", "")
    if cmd:
        body_parts.append(f'<span class="field-label">Command Executed</span><pre class="cmd">{_esc(cmd.strip())}</pre>')

    # Detection status
    fired_sids = f.get("fired_sids", [])
    zeek_notices = f.get("zeek_notices", [])
    if fired_sids:
        sid_str = ", ".join(str(s) for s in fired_sids)
        body_parts.append(
            f'<span class="field-label">Detection Status</span>'
            f'<span class="detection-yes">&#10003; Suricata Alert Triggered</span>'
            f'<br><span class="sid-list">SIDs: {_esc(sid_str)}</span>'
        )
    else:
        body_parts.append(
            f'<span class="field-label">Detection Status</span>'
            f'<span class="detection-no">&#10007; No Suricata Rule Matched</span>'
        )
    if zeek_notices:
        notice_str = ", ".join(zeek_notices)
        body_parts.append(f'<span class="sid-list">Zeek Notices: {_esc(notice_str)}</span>')

    # Zeek protocol signals
    zeek_signals = f.get("zeek_signals", "")
    if zeek_signals:
        body_parts.append(
            f'<span class="field-label">Zeek Protocol Intelligence</span>'
            f'<div class="notes-text" style="font-family:monospace; font-size:0.8rem; '
            f'background:#f0f7ff; padding:0.5rem; border-radius:4px; border-left:3px solid #17a2b8;">'
            f'{_esc(zeek_signals)}</div>'
        )

    # Notes
    notes = f.get("notes", "")
    if notes:
        body_parts.append(f'<span class="field-label">Analysis</span><div class="notes-text">{_esc(notes)}</div>')

    # Remediation
    remediation = f.get("remediation", "")
    if remediation:
        body_parts.append(f'<span class="field-label">Recommended Remediation</span><div class="notes-text" style="color:#0d6efd;">{_esc(remediation)}</div>')

    # Timestamp
    ts = f.get("ts", "")
    if ts:
        body_parts.append(f'<div class="ts-text">Executed: {_esc(ts)}</div>')

    body_html = "\n".join(body_parts)
    return f'<div class="finding-card">{header}<div class="finding-body">{body_html}</div></div>'


def _build_findings_section(enriched):
    parts = ['<h2>Detailed Findings</h2>']
    if not enriched:
        parts.append('<p>No findings recorded.</p>')
        return "\n".join(parts)

    for f in enriched:
        parts.append(_build_finding_card(f))
    return "\n".join(parts)


def _build_detection_layers(enriched):
    """Build a Suricata vs Zeek dual-layer detection comparison."""
    parts = ['<h2>Detection Layer Analysis: Suricata vs Zeek</h2>',
             '<p>Each attack is evaluated against both detection layers. An attack may be '
             'invisible to Suricata (no signature) but visible to Zeek (protocol metadata, '
             'JA3 fingerprints, behavioral signals), or vice versa.</p>']

    # Classify each finding by layer visibility
    both = []
    suricata_only = []
    zeek_only = []
    neither = []

    for f in enriched:
        has_suricata = bool(f.get("fired_sids"))
        has_zeek = bool(f.get("zeek_notices")) or bool(f.get("zeek_signals")) or f.get("confidence") == "behavioral"
        if has_suricata and has_zeek:
            both.append(f)
        elif has_suricata:
            suricata_only.append(f)
        elif has_zeek:
            zeek_only.append(f)
        else:
            neither.append(f)

    total = len(enriched)
    # Summary boxes
    parts.append(f"""
    <div class="stat-boxes">
        <div class="stat-box" style="background:#155724;"><div class="num">{len(both)}</div><div class="label">Both Layers</div></div>
        <div class="stat-box" style="background:#28a745;"><div class="num">{len(suricata_only)}</div><div class="label">Suricata Only</div></div>
        <div class="stat-box" style="background:#17a2b8;"><div class="num">{len(zeek_only)}</div><div class="label">Zeek Only</div></div>
        <div class="stat-box" style="background:#dc3545;"><div class="num">{len(neither)}</div><div class="label">Neither Layer</div></div>
    </div>
    """)

    # Insight narrative
    zeek_coverage = len(both) + len(zeek_only)
    suri_coverage = len(both) + len(suricata_only)
    any_coverage = len(both) + len(suricata_only) + len(zeek_only)
    parts.append('<div class="summary-text">')
    parts.append(f'<p>Suricata detected <strong>{suri_coverage}/{total}</strong> attacks via signatures. '
                 f'Zeek provided visibility into <strong>{zeek_coverage}/{total}</strong> attacks via protocol metadata. '
                 f'Combined, <strong>{any_coverage}/{total}</strong> attacks had at least one detection signal. ')
    if zeek_only:
        parts.append(
            f'<strong>{len(zeek_only)} attacks were visible only through Zeek</strong> (protocol logs, '
            f'JA3/HASSH fingerprints, or behavioral indicators) -- these represent opportunities '
            f'to write Suricata rules informed by Zeek metadata, or to build Zeek-native detections.')
    if neither:
        parts.append(
            f' <strong>{len(neither)} attacks were invisible to both layers</strong> -- these are '
            f'true blind spots requiring new detection capability.')
    parts.append('</p></div>')

    # Table of Zeek-only detections (high value -- Zeek saw it, Suricata didn't)
    if zeek_only:
        parts.append('<h3>Zeek-Only Visibility (Suricata gap, Zeek signal present)</h3>')
        parts.append('<p style="font-size:0.85rem; color:#495057;">These attacks were not caught by '
                     'Suricata signatures but Zeek protocol analyzers captured actionable metadata.</p>')
        parts.append('<table class="gap-table" style="border-left:3px solid #17a2b8;">'
                     '<thead><tr style="background:#17a2b8;">'
                     '<th>Attack</th><th>MITRE</th><th>Zeek Evidence</th><th>Recommendation</th>'
                     '</tr></thead><tbody>')
        for f in zeek_only:
            zeek_ev = f.get("zeek_signals", "") or f.get("notes", "")
            remed = f.get("remediation", "")
            parts.append(
                f'<tr>'
                f'<td><strong>{_esc(f.get("probe", ""))}</strong></td>'
                f'<td>{_esc(f.get("mitre_id", ""))}</td>'
                f'<td style="font-family:monospace; font-size:0.8rem;">{_esc(zeek_ev[:200])}</td>'
                f'<td>{_esc(remed[:150])}</td>'
                f'</tr>'
            )
        parts.append('</tbody></table>')

    # Table of true blind spots
    if neither:
        parts.append('<h3>True Blind Spots (invisible to both layers)</h3>')
        parts.append('<table class="gap-table"><thead><tr>'
                     '<th>Attack</th><th>Severity</th><th>MITRE</th><th>Tool</th><th>Notes</th>'
                     '</tr></thead><tbody>')
        for f in neither:
            sev = f.get("severity", "Medium")
            sev_color = SEVERITY_COLORS.get(sev, "#6c757d")
            parts.append(
                f'<tr>'
                f'<td><strong>{_esc(f.get("probe", ""))}</strong></td>'
                f'<td><span style="color:{sev_color}; font-weight:600;">{_esc(sev)}</span></td>'
                f'<td>{_esc(f.get("mitre_id", ""))}</td>'
                f'<td><code>{_esc(f.get("tool_used", ""))}</code></td>'
                f'<td>{_esc(f.get("notes", "")[:150])}</td>'
                f'</tr>'
            )
        parts.append('</tbody></table>')

    return "\n".join(parts)


def _build_gap_analysis(gaps):
    if not gaps:
        return '<h2>Gap Analysis</h2><p>No detection gaps identified.</p>'

    # Group by tactic
    by_tactic = {}
    for g in gaps:
        t = g.get("mitre_tactic") or "Unknown"
        by_tactic.setdefault(t, []).append(g)

    parts = ['<h2>Gap Analysis</h2>',
             '<p>Probes that reached the wire with no matching Suricata signature, grouped by MITRE ATT&amp;CK tactic.</p>']

    for tactic, items in sorted(by_tactic.items()):
        parts.append(f'<h3>{_esc(tactic)} ({len(items)} gaps)</h3>')
        parts.append('<table class="gap-table"><thead><tr>'
                     '<th>Probe</th><th>Severity</th><th>MITRE</th><th>Tool</th><th>Notes</th>'
                     '</tr></thead><tbody>')
        for g in items:
            sev = g.get("severity", "Medium")
            sev_color = SEVERITY_COLORS.get(sev, "#6c757d")
            parts.append(
                f'<tr>'
                f'<td><strong>{_esc(g.get("probe", ""))}</strong></td>'
                f'<td><span style="color:{sev_color}; font-weight:600;">{_esc(sev)}</span></td>'
                f'<td>{_esc(g.get("mitre_id", ""))}</td>'
                f'<td><code>{_esc(g.get("tool_used", ""))}</code></td>'
                f'<td>{_esc(g.get("notes", ""))}</td>'
                f'</tr>'
            )
        parts.append('</tbody></table>')

    return "\n".join(parts)


def _build_appendix(ledger_path):
    return f"""
    <h2>Appendix</h2>

    <h3>Severity Definitions</h3>
    <div class="severity-def">
        <div class="sd-item" style="border-color:#dc3545;"><strong>Critical</strong> -- Undetected initial-access or execution-stage attack. Immediate rule-engineering required.</div>
        <div class="sd-item" style="border-color:#fd7e14;"><strong>High</strong> -- Undetected C2, exfiltration, or credential-access activity. High-priority gap.</div>
        <div class="sd-item" style="border-color:#ffc107;"><strong>Medium</strong> -- Undetected discovery, lateral movement, or collection. Moderate-priority gap.</div>
        <div class="sd-item" style="border-color:#17a2b8;"><strong>Low</strong> -- Undetected reconnaissance or probe error. Lower priority.</div>
        <div class="sd-item" style="border-color:#6c757d;"><strong>Info</strong> -- Detection is working (a Suricata signature fired).</div>
    </div>

    <h3>Methodology</h3>
    <p>This assessment was conducted using an automated purple-team agent operating on an authorized lab
    environment. The agent iteratively: (1) baselines the Suricata eve.json line count on the sensor,
    (2) executes a probe command from the attacker box against the victim IP, (3) diffs new alerts on
    the sensor, and (4) classifies the result. Probes are drawn from a curated pool covering CVE exploits,
    C2 framework emulation, data exfiltration, identity abuse, and supply-chain scenarios.</p>

    <details>
        <summary>Raw Findings Ledger</summary>
        <p style="margin-top:0.5rem;">Full JSONL trace: <code>{_esc(ledger_path.name)}</code> (alongside this report)</p>
    </details>
"""


def write_navigator_layer(reports_dir, ts, enriched):
    """Export MITRE ATT&CK Navigator JSON layer for visual heatmap diffing."""
    technique_map = {}
    for f in enriched:
        tid = f.get("mitre_id", "")
        if not tid:
            continue
        verdict = f.get("verdict", "").upper()
        probe = f.get("probe", "")
        if tid not in technique_map:
            technique_map[tid] = {"probes": [], "verdicts": set()}
        technique_map[tid]["probes"].append(probe)
        technique_map[tid]["verdicts"].add(verdict)

    techniques = []
    for tid, info in technique_map.items():
        verdicts = info["verdicts"]
        probes = info["probes"]
        if "UNDETECTED" in verdicts:
            color = "#dc3545"
            score = 0
        elif "DETECTED" in verdicts:
            color = "#28a745"
            score = 100
        elif "ERROR" in verdicts:
            color = "#ffc107"
            score = 50
        else:
            color = "#6c757d"
            score = 25
        comment = f"{', '.join(verdicts)}: {', '.join(probes[:5])}"
        entry = {"techniqueID": tid, "color": color, "score": score, "comment": comment, "enabled": True}
        # Handle sub-techniques
        if "." in tid:
            entry["tactic"] = ""
        techniques.append(entry)

    layer = {
        "name": f"Purple Run {ts}",
        "versions": {"attack": "18", "navigator": "5.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Purple-team detection coverage from run {ts}",
        "techniques": techniques,
        "gradient": {"colors": ["#dc3545", "#ffc107", "#28a745"], "minValue": 0, "maxValue": 100},
        "legendItems": [
            {"label": "Undetected", "color": "#dc3545"},
            {"label": "Detected", "color": "#28a745"},
            {"label": "Error", "color": "#ffc107"},
        ],
    }

    out = reports_dir / f"navigator-layer-{ts}.json"
    out.write_text(json.dumps(layer, indent=2), encoding="utf-8")
    print(f"[purple-agent] navigator: {out}")


def write_html_report(reports_dir, ts, ledger_path, args, probes_yaml_path=None):
    findings = _load_findings(ledger_path)
    enriched = _enrich_findings(findings, probes_yaml_path)

    buckets = {"DETECTED": [], "UNDETECTED": [], "ERROR": [], "OTHER": []}
    for f in enriched:
        v = f.get("verdict", "").upper()
        buckets.get(v, buckets["OTHER"]).append(f)

    css = _build_css()
    cover = _build_cover(ts, args)
    exec_summary = _build_exec_summary(enriched, buckets)
    suricata_alerts = _build_suricata_alerts(enriched)
    detection_layers = _build_detection_layers(enriched)
    mitre_matrix = _build_mitre_matrix(enriched)
    findings_html = _build_findings_section(enriched)
    gap_analysis = _build_gap_analysis(buckets["UNDETECTED"])
    appendix = _build_appendix(ledger_path)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Purple-Team Report {_esc(ts)}</title>
    <style>{css}</style>
</head>
<body>
{cover}
{exec_summary}
{suricata_alerts}
{detection_layers}
{mitre_matrix}
{findings_html}
{gap_analysis}
{appendix}
</body>
</html>"""

    out = reports_dir / f"report-{ts}.html"
    out.write_text(html, encoding="utf-8")
    print(f"[purple-agent] report written: {out}")
    print(f"[purple-agent] findings:       {ledger_path}")

    # ATT&CK Navigator layer
    write_navigator_layer(reports_dir, ts, enriched)


# ============================================================================
#  cli
# ============================================================================

def parse_args():
    p = argparse.ArgumentParser(
        description="Autonomous purple-team probe runner for the Suricata+Zeek lab.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    p.add_argument("--attacker-ip", required=True, help="Attacker public IP (SSH target)")
    p.add_argument("--sensor-ip", required=True, help="Sensor public IP (SSH target, read-only use)")
    p.add_argument("--victim-ip", required=True, help="Victim PRIVATE IP (attack target)")
    p.add_argument("--key", required=True, help="SSH private key file path")
    p.add_argument("--budget", type=int, default=30, help="Max agent turns (default 30)")
    p.add_argument(
        "--probe-pool",
        help="Path to probes.yaml (default: probes.yaml in script dir)",
    )
    return p.parse_args()


def main():
    args = parse_args()
    asyncio.run(run_agent(args))


if __name__ == "__main__":
    main()
