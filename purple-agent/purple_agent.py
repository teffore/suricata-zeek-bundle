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
_max_attacks: int | None = None  # hard cap, enforced inside record_finding
# Sensor-log line counts captured at run start so audit + sweep can tail
# forward from these baselines -- avoids the byte-count tail truncation bug
# that silently drops the early half of the run window when logs are large.
_eve_before_lines: int | None = None
_notice_before_lines: int | None = None
_intel_before_lines: int | None = None


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
    "T1078.004": {"tactic": "Initial Access", "name": "Valid Accounts: Cloud Accounts", "url": "https://attack.mitre.org/techniques/T1078/004/"},
    "T1602": {"tactic": "Collection", "name": "Data from Configuration Repository", "url": "https://attack.mitre.org/techniques/T1602/"},
    "T1556": {"tactic": "Credential Access", "name": "Modify Authentication Process", "url": "https://attack.mitre.org/techniques/T1556/"},
    "T1548": {"tactic": "Privilege Escalation", "name": "Abuse Elevation Control Mechanism", "url": "https://attack.mitre.org/techniques/T1548/"},
    "T1098": {"tactic": "Persistence", "name": "Account Manipulation", "url": "https://attack.mitre.org/techniques/T1098/"},
    "T1546": {"tactic": "Persistence", "name": "Event Triggered Execution", "url": "https://attack.mitre.org/techniques/T1546/"},
    "T1187": {"tactic": "Credential Access", "name": "Forced Authentication", "url": "https://attack.mitre.org/techniques/T1187/"},
    "T1649": {"tactic": "Credential Access", "name": "Steal or Forge Authentication Certificates", "url": "https://attack.mitre.org/techniques/T1649/"},
    "T1526": {"tactic": "Discovery", "name": "Cloud Service Discovery", "url": "https://attack.mitre.org/techniques/T1526/"},
    "T1552.005": {"tactic": "Credential Access", "name": "Unsecured Credentials: Cloud Instance Metadata API", "url": "https://attack.mitre.org/techniques/T1552/005/"},
    "T1557.001": {"tactic": "Credential Access", "name": "Adversary-in-the-Middle: LLMNR/NBT-NS Poisoning", "url": "https://attack.mitre.org/techniques/T1557/001/"},
    "T1557.003": {"tactic": "Credential Access", "name": "Adversary-in-the-Middle: DHCP Spoofing", "url": "https://attack.mitre.org/techniques/T1557/003/"},
    "T1589.002": {"tactic": "Reconnaissance", "name": "Gather Victim Identity Information: Email Addresses", "url": "https://attack.mitre.org/techniques/T1589/002/"},
    "T1592.004": {"tactic": "Reconnaissance", "name": "Gather Victim Host Information: Client Configurations", "url": "https://attack.mitre.org/techniques/T1592/004/"},
    "T1090.004": {"tactic": "Command and Control", "name": "Proxy: Domain Fronting", "url": "https://attack.mitre.org/techniques/T1090/004/"},
    "T1595.003": {"tactic": "Reconnaissance", "name": "Active Scanning: Wordlist Scanning", "url": "https://attack.mitre.org/techniques/T1595/003/"},
    "T1021.006": {"tactic": "Lateral Movement", "name": "Remote Services: Windows Remote Management", "url": "https://attack.mitre.org/techniques/T1021/006/"},
    "T1016": {"tactic": "Discovery", "name": "System Network Configuration Discovery", "url": "https://attack.mitre.org/techniques/T1016/"},
    "T1083": {"tactic": "Discovery", "name": "File and Directory Discovery", "url": "https://attack.mitre.org/techniques/T1083/"},
    "T1087": {"tactic": "Discovery", "name": "Account Discovery", "url": "https://attack.mitre.org/techniques/T1087/"},
    "T1135": {"tactic": "Discovery", "name": "Network Share Discovery", "url": "https://attack.mitre.org/techniques/T1135/"},
    "T1212": {"tactic": "Credential Access", "name": "Exploitation for Credential Access", "url": "https://attack.mitre.org/techniques/T1212/"},
    "T1530": {"tactic": "Collection", "name": "Data from Cloud Storage", "url": "https://attack.mitre.org/techniques/T1530/"},
    "T1613": {"tactic": "Discovery", "name": "Container and Resource Discovery", "url": "https://attack.mitre.org/techniques/T1613/"},
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

# Ambient/canary SIDs that fire on background traffic — separated from
# "relevant" detections during report post-processing but kept in the ledger.
NOISE_FLOOR_SIDS = {"9000003", "2001219"}

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
    "include remediation (what Suricata rule pattern would close the gap). "
    "zeek_notices and zeek_weird come from DIFFERENT Zeek logs -- keep them "
    "separate: notice.log entries (namespaced like 'Scan::Port_Scan') go in "
    "zeek_notices, weird.log anomalies (e.g. 'HTTP_version_mismatch') go in "
    "zeek_weird.",
    {
        "probe_name": str,
        "verdict": str,
        "fired_sids": str,
        "zeek_notices": str,
        "zeek_weird": str,
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
    # Hard-cap enforcement: refuse new records once --max-attacks is hit.
    if _max_attacks is not None and _ledger_path is not None and _ledger_path.exists():
        current = sum(1 for line in _ledger_path.open(encoding="utf-8") if line.strip())
        if current >= _max_attacks:
            return {
                "content": [{
                    "type": "text",
                    "text": (
                        f"ATTACK CAP REACHED ({_max_attacks}). record_finding will not "
                        f"accept further entries. Do NOT call any more tools. "
                        f"Reply with exactly 'PURPLE RUN COMPLETE' and stop."
                    ),
                }]
            }
    fired_sids = [s.strip() for s in args.get("fired_sids", "").split(",") if s.strip()]
    zeek_notices = [s.strip() for s in args.get("zeek_notices", "").split(",") if s.strip()]
    zeek_weird = [s.strip() for s in args.get("zeek_weird", "").split(",") if s.strip()]
    claimed_confidence = (args.get("confidence") or "").lower()

    # Normalize confidence against hard evidence -- the LLM tends to inflate
    # "behavioral" onto plain protocol visibility. See _normalize_confidence().
    normalized_confidence, was_corrected = _normalize_confidence(
        claimed_confidence, fired_sids, zeek_notices
    )
    correction_note = ""
    if was_corrected:
        if claimed_confidence == "behavioral":
            correction_note = (
                f" [confidence auto-corrected from 'behavioral' to 'none' because "
                f"zeek_notices is empty -- 'behavioral' requires a notice.log or weird.log "
                f"entry, not just protocol visibility. Put protocol metadata in zeek_signals.]"
            )
        else:
            correction_note = (
                f" [confidence auto-corrected from '{claimed_confidence}' to 'none' because "
                f"fired_sids is empty -- high/partial require a Suricata SID]"
            )

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "probe": args.get("probe_name", ""),
        "verdict": args.get("verdict", ""),
        "fired_sids": fired_sids,
        "zeek_notices": zeek_notices,
        "zeek_weird": zeek_weird,
        "notes": args.get("notes", ""),
        "tool_used": args.get("tool_used", ""),
        "command_executed": args.get("command_executed", ""),
        "mitre_id": args.get("mitre_id", ""),
        "confidence": normalized_confidence,
        "claimed_confidence": claimed_confidence if correction_note else "",
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
                "text": (
                    f"recorded: {entry['probe']} -> {entry['verdict']} "
                    f"(sids={len(fired_sids)}, notices={len(zeek_notices)}, "
                    f"weird={len(zeek_weird)})"
                    + correction_note
                ),
            }
        ]
    }


# ============================================================================
#  system prompt
# ============================================================================

POOL_SECTION = """\
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
"""


POOL_FREE_SECTION = """\
## Pool-free mode: improvise every probe

You have NO probe pool file to read. Invent each probe from the taxonomy below.
Aim for variety and breadth -- DO NOT funnel into the same 5-10 probes every
run. Pick categories you haven't exercised yet in this run, mix well-known CVE
patterns with active-campaign TTPs, and occasionally attempt something novel.

Each probe you run must:
  - Be ONE bash command runnable on Kali (single line; use `;` / `&&` for chains)
  - Produce observable network traffic toward the victim IP (or authorized
    outbound SaaS like api.openai.com for SNI exfil)
  - Have `--max-time 5` on curl, `timeout N` on nc/python, etc. (no hangs)
  - Use the literal victim IP from your lab endpoints (no {{placeholder}})

### Attack taxonomy (pick a mix each run)

**Edge-device CVE exploitation (T1190)** -- HTTP requests to vulnerable paths:
  PAN-OS GlobalProtect, FortiOS SSL-VPN, Ivanti Connect Secure, SharePoint
  ToolShell (CVE-2025-53770), CrushFTP, Oracle EBS SSRF, SAP NetWeaver
  metadatauploader, CitrixBleed, TeamCity CVE-2024-27198, ScreenConnect,
  Confluence OGNL, ProxyShell, Cisco SD-WAN / FMC.

**Modern C2 beacon replay (T1071.001)** -- HTTP/S requests mimicking default
  malleable profiles: Sliver default URIs, Havoc __cfduid, Cobalt Strike
  jquery, Brute Ratel /api/search, Mythic Apollo/Medusa /api/v1.4/*,
  Merlin HTTP/2, AdaptixC2.

**Commodity malware checkin (T1071.001 / T1041)** -- Lumma, DarkGate,
  SocGholish, NetSupport RAT, Pikabot, StealC, RedLine, Formbook.

**SaaS / LLM SNI exfil (T1567, T1102)** -- TLS to: api.openai.com,
  api.anthropic.com, generativelanguage.googleapis.com, huggingface.co,
  hooks.slack.com, gist.github.com, webhook.site, api.telegram.org,
  discord.com/api/webhooks, pipedream.com, ngrok-free.app, trycloudflare.com.

**DNS abuse (T1572, T1568.002, T1071.004)** -- DoH to cloudflare-dns.com /
  dns.google, TXT record base64 exfil, rapid NXDOMAIN bursts (DGA),
  long-subdomain hex queries, dig AXFR attempts.

**Identity / cloud-SSO abuse (T1528, T1556, T1078.004)** -- Microsoft OAuth
  device-code bursts, Okta /.well-known enumeration, GitHub Actions OIDC
  endpoint, AzureHound UA against graph.microsoft.com, AWS IMDSv1 SSRF
  to 169.254.169.254, evilginx 8-char lure URIs.

**AD / lateral movement (T1558, T1021, T1087.002)** -- Impacket
  GetUserSPNs / GetNPUsers / secretsdump / psexec / wmiexec / dcomexec,
  SMB null-session enum, SharpHound-style LDAP SDFlags=0x5, Certipy ESC1
  find, kerbrute userenum, NetExec SMB spray, PetitPotam / DFSCoerce.

**Scanning (T1595.001/002)** -- nmap SYN / Xmas / FIN / NULL / connect /
  ACK scans, nikto HTTP scan, nuclei with -tags kev, feroxbuster content
  discovery, wafw00f, sqlmap error-based injection.

**Covert channels (T1095, T1572)** -- ICMP large-payload, SSH dynamic
  port-forward, QUIC/HTTP3 beacons, ssh-banner-spoof, paramiko HASSH.

**Supply chain (T1195.002)** -- npm registry pulls, PyPI / pythonhosted,
  Docker Hub (registry-1.docker.io) pulls, GitHub raw content,
  HuggingFace dataset pulls, typosquat SNI variants.

**Cryptominer (T1496)** -- stratum login to supportxmr / nanopool /
  minexmr, XMRig default UA patterns, coinhive legacy patterns.

### Probe-naming convention

Use kebab-case, include tool or CVE: `panos-cve-2024-3400-sessid`,
`sliver-default-urls`, `azurehound-graph-enum`. If you improvise a variant,
add a suffix: `panos-cve-2024-3400-evasion-unicode`.

### Attribution rule (critical for pool-free)

Without an `expected_sids` anchor, it is easy to over-attribute ambient
alerts to your probe. Before listing a SID in `fired_sids`, confirm its
alert's `dest_ip` matches your probe's INTENDED TARGET (victim IP for
victim-targeting probes; the external endpoint -- SaaS SNI host, DoH
resolver, IMDS 169.254.169.254, C2 IP -- for outbound probes) AND its
timestamp is after BEFORE. Everything else is ambient and belongs in
`notes`, not `fired_sids`. Canary SIDs 2001219 and 9000003 fire on
background sensor traffic -- they count as probe-attributable ONLY when
the probe is itself a scan-type technique.
"""


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

## Fired SIDs: record only probe-attributable SIDs

`fired_sids` must contain ONLY SIDs whose alert is causally tied to THIS
probe. An alert is causally tied when BOTH of these hold:
  (a) its `dest_ip` equals the probe's INTENDED TARGET -- which is the
      victim IP for victim-targeting probes, OR the probe's external
      endpoint for outbound probes (SaaS SNI exfil -> api.openai.com /
      huggingface.co / hooks.slack.com; DoH/DGA -> 1.1.1.1 / 8.8.8.8 /
      cloudflare-dns.com; IMDS SSRF -> 169.254.169.254; C2 beacon ->
      the C2 IP). Pick the ip or hostname that YOUR probe actually
      reaches out to, not blindly the victim IP.
  (b) its timestamp falls between BEFORE and "now" (the baseline window).

Canary / ambient SIDs (2001219 "ET SCAN Potential SSH Scan", 9000003 local
probe-visibility rule) fire on background sensor traffic continuously and
must be EXCLUDED from `fired_sids` unless the probe is itself a scan-type
technique (nmap SYN/Xmas/stealth, hping3 flood, ssh password spray,
rapid port enumeration) -- in those cases the canary IS the intended
detection and belongs in `fired_sids`. For non-scan probes (CVE exploits,
SaaS exfil, C2 beacons, web attacks), list canary SIDs in `notes` as
"ambient canaries observed: 2001219, 9000003" but keep them OUT of
`fired_sids`.

When setting the verdict:
  - DETECTED   = at least one probe-attributable SID fired (per the
                 causal-attribution rule above).
  - UNDETECTED = no probe-attributable SIDs fired. `fired_sids` should be
                 empty or contain ONLY canaries-on-a-scan-probe.
  - FP         = a SID fired, was causally attributable to this probe's
                 traffic, but the signature is unrelated to the technique
                 (e.g. a generic "POST to /" rule fires on a CVE exploit).

{probe_source_section}

## Per-probe iteration loop

IMPORTANT: Minimize SSH calls. Use compound commands to batch work into fewer
tool invocations. Each SSH call reuses connections (ControlMaster) but each
Bash tool call is still a turn.

For each probe you attempt:

1. BASELINE + PROBE:
   IMPORTANT: baseline BOTH Suricata (line count) AND Zeek (sensor epoch time).
   Without the Zeek timestamp baseline, stale notice/weird entries from earlier
   probes contaminate the next check -- you'll misattribute old detections
   to the current probe.

   Option A (simpler, 3 calls):
     BEFORE=$(ssh <sensor> "sudo wc -l /var/log/suricata/eve.json | awk '{{print \\$1}}'")
     ZBEFORE=$(ssh <sensor> "date +%s")
     WBEFORE=$(ssh <sensor> "sudo wc -l /opt/zeek/logs/current/weird.log 2>/dev/null | awk '{{print \\$1}}'")
     ssh <attacker> "<probe command>"
     sleep 2  # let Zeek's ASCII writer flush buffered dns/http/conn log entries
   Option B (one call, faster -- preferred when the probe is a simple one-liner):
     read BEFORE ZBEFORE WBEFORE < <(ssh <sensor> "echo \\$(sudo wc -l /var/log/suricata/eve.json | awk '{{print \\$1}}') \\$(date +%s) \\$(sudo wc -l /opt/zeek/logs/current/weird.log 2>/dev/null | awk '{{print \\$1}}')"); \\
     ssh <attacker> "<probe command>"; sleep 2
   Use --max-time 5 on curl and `timeout N` on nc/long-runners. The sleep
   matters: Zeek buffers logs ~1-2s before flushing, so a check done
   immediately after a fast probe misses entries that ARE about to appear.

   WHY WBEFORE: weird.log can log 80K+ events per second during volumetric
   probes (SYN flood, rapid DNS bursts). A byte-count tail (tail -c 20000)
   reads random 20KB of that flood and misses everything. Line-count
   baseline + tail -n +N captures every entry logged after the baseline.

2. CHECK (ONE compound SSH call to sensor -- do NOT split into separate calls):
     ssh <sensor> "
       echo '=== ALERTS ===';
       sudo tail -n +\\$((BEFORE + 1)) /var/log/suricata/eve.json 2>/dev/null \\
         | jq -c 'if .event_type == \\"alert\\" then {{type:\\"alert\\", sid:.alert.signature_id, sig:.alert.signature}}
                   elif .event_type == \\"anomaly\\" then {{type:\\"anomaly\\", layer:.anomaly.layer, event:.anomaly.event}}
                   elif .event_type == \\"tls\\" then {{type:\\"tls\\", sni:.tls.sni, ja3:.tls.ja3.hash}}
                   else empty end' | sort -u | head -30;
       echo '=== ZEEK-NOTICES ===';
       sudo tail -c 50000 /opt/zeek/logs/current/notice.log 2>/dev/null \\
         | jq -rc 'select((.ts|tonumber) > '$ZBEFORE') | .note' 2>/dev/null | sort -u | tail -10;
       echo '=== ZEEK-SSH ===';
       sudo tail -c 20000 /opt/zeek/logs/current/ssh.log 2>/dev/null \\
         | jq -rc 'select((.ts|tonumber) > '$ZBEFORE') | {{client, hassh}}' 2>/dev/null | tail -5;
       echo '=== ZEEK-TLS ===';
       sudo tail -c 20000 /opt/zeek/logs/current/ssl.log 2>/dev/null \\
         | jq -rc 'select((.ts|tonumber) > '$ZBEFORE') | {{server_name, ja3}}' 2>/dev/null | tail -5;
       echo '=== ZEEK-DNS ===';
       sudo tail -c 20000 /opt/zeek/logs/current/dns.log 2>/dev/null \\
         | jq -rc 'select((.ts|tonumber) > '$ZBEFORE') | {{query, qtype_name, rcode_name}}' 2>/dev/null | tail -10;
       echo '=== ZEEK-HTTP ===';
       sudo tail -c 30000 /opt/zeek/logs/current/http.log 2>/dev/null \\
         | jq -rc 'select((.ts|tonumber) > '$ZBEFORE') | {{host, uri: (.uri // \\"\\" | .[0:80]), method, user_agent: (.user_agent // \\"\\" | .[0:60]), status_code}}' 2>/dev/null | tail -10;
       echo '=== ZEEK-WEIRD ===';
       sudo tail -n +\\$((WBEFORE + 1)) /opt/zeek/logs/current/weird.log 2>/dev/null \\
         | jq -rc '.name' 2>/dev/null | sort | uniq -c | sort -rn | head -20;
       echo '=== ZEEK-CONN ===';
       sudo tail -c 50000 /opt/zeek/logs/current/conn.log 2>/dev/null \\
         | jq -rc 'select((.ts|tonumber) > '$ZBEFORE') | [.[\\"id.resp_h\\"], (.[\\"id.resp_p\\"]|tostring), .proto, .conn_state] | @tsv' 2>/dev/null | sort -u | head -20
     "
   Every jq filter includes `select((.ts|tonumber) > '$ZBEFORE')` so ONLY
   entries logged after the baseline appear. An empty section for a log means
   this probe did not produce activity in that protocol -- not that the log
   itself is empty.
   This single SSH call gives you alerts, anomalies, TLS SNI, and all relevant
   Zeek protocol logs. Two DIFFERENT Zeek logs matter here:
     - notice.log entries (namespaced, e.g. "Scan::Port_Scan",
       "ProtocolDetector::Protocol_Found") are opinionated Zeek detections.
       They belong in zeek_notices.
     - weird.log entries (non-namespaced, e.g. "HTTP_version_mismatch",
       "unescaped_%_in_URI") are protocol-parser anomalies, lower-signal.
       They belong in zeek_weird -- NOT in zeek_notices.
   A notice.log entry qualifies for confidence="behavioral". weird-only (no
   notice) does NOT -- weird is hunting context, not detection.
   Plain protocol metadata in ssh.log/ssl.log/dns.log/http.log without a
   corresponding notice is VISIBILITY only -- record it in zeek_signals but
   keep confidence="none".
   You may omit Zeek sections not relevant to the probe type to keep output short.

3. CLASSIFY -- call the `record_finding` tool with:
     - probe_name        -- the pool entry's `name` (or a descriptive name if improvised)
     - verdict           -- DETECTED / UNDETECTED / ERROR / FP
     - fired_sids        -- CSV of probe-attributable SIDs ONLY (e.g.
                            "2047929,2024792"). A SID is attributable ONLY if
                            BOTH (a) its alert's `dest_ip` matches the probe's
                            INTENDED TARGET (victim IP for victim-targeting
                            probes; the external endpoint -- SaaS SNI host, DoH
                            resolver, IMDS 169.254.169.254, C2 IP -- for
                            outbound probes) AND (b) its timestamp is after
                            BEFORE. Canary SIDs (2001219, 9000003) belong here
                            ONLY if the probe is itself a scan-type
                            (nmap/hping3/ssh-spray); otherwise put them in
                            `notes` as "ambient canaries observed: X" and keep
                            them OUT of this field.
     - zeek_notices      -- CSV of notice.log entries only (namespaced,
                            "Module::Event"). Empty string if notice.log was quiet.
     - zeek_weird        -- CSV of weird.log entry names (non-namespaced, e.g.
                            "HTTP_version_mismatch"). Empty string if weird.log
                            was quiet. Do NOT mix these into zeek_notices.
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
     - zeek_signals      -- ONLY transcribe fields that appeared in your CHECK
                            step output. NEVER fabricate. Do NOT write "would
                            show", "likely logged", "typically", or invent Zeek
                            event names (like RESPONSE_HEADER_REPETITION) that
                            weren't literally in your output.

                            If a log section was empty in your CHECK output,
                            write it as "empty" (e.g. "ssl.log: empty").
                            If the probe was fast and Zeek's ~1-2s flush lag
                            probably hid entries, write "empty (probable Zeek
                            flush latency)" -- but ONLY if the probe ran in
                            under 2 seconds.

                            Format template:
                              "ssl.log: sni=X ja3=Y | dns.log: query=Z rcode=W |
                               http.log: host=H uri=U method=M status=200 |
                               conn.log: dst=IP port=80 proto=tcp state=SF |
                               ssh.log: empty | weird.log: empty"

                            Omit logs that are empty AND irrelevant to the probe.
                            Do NOT narrate or editorialize -- no "proof of
                            visibility", no "strong overlap suggests X",
                            no "policy tuning needed". Just the observed fields.

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

When you've either (a) worked through the pool, (b) hit the turn budget, OR
(c) hit the attack cap -- reply with the literal phrase "PURPLE RUN COMPLETE"
and stop calling tools. The orchestrator will gather your findings and write
the final report.

IMPORTANT: when an attack cap IS set (see "Attack cap" below), do NOT
self-terminate just because you think novel candidates are exhausted --
there is ALWAYS another variant worth trying (different tool, encoding,
port, protocol wrapper, user-agent, evasion twist). Keep improvising until
you fill the cap or hit the turn budget. "I've covered enough categories"
is NOT a valid reason to stop short of the cap. Only terminate early via
(d) if there is NO attack cap set AND you genuinely cannot invent a new
probe that would add distinct sensor signal.

Your budget: {max_turns} turns. Pace yourself -- each probe iteration should
use 2-3 turns (baseline+probe, check, classify). Batching commands into fewer
Bash calls is critical for throughput.

Attack cap: {max_attacks_str}. When set, record_finding will REFUSE further
calls once the cap is reached (returning an "ATTACK CAP REACHED" message).
When it refuses, stop immediately -- do NOT retry, do NOT batch more probes.
Respect the cap by NOT queuing more probes than remaining slots.
"""


# ============================================================================
#  runner
# ============================================================================

async def run_agent(args):
    global _ledger_path, _max_attacks, _eve_before_lines, _notice_before_lines, _intel_before_lines

    REPORTS_DIR.mkdir(exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    _ledger_path = REPORTS_DIR / f"findings-{ts}.jsonl"
    _ledger_path.touch()
    _max_attacks = args.max_attacks

    # Capture sensor log line counts RIGHT NOW so the audit + sweep can read
    # forward from these offsets. A byte-count tail silently drops the early
    # half of the run window when a log is large (Run 3: 34MB eve.json, run
    # start at byte 15MB, tail -c 5MB only reached back to byte 29MB -> 10
    # false "overclaims"). notice.log / intel.log suffer the same class of
    # bug, so capture baselines for all three.
    import subprocess
    ssh_base = (
        f"ssh -i {args.key} -o StrictHostKeyChecking=no "
        f"-o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 "
        f"ubuntu@{args.sensor_ip}"
    )
    def _capture_lines(remote_path, label):
        try:
            r = subprocess.run(
                ["bash", "-c",
                 f"{ssh_base} \"sudo wc -l {remote_path} 2>/dev/null | awk '{{print \\$1}}'\""],
                capture_output=True, text=True, timeout=30,
            )
            n = int((r.stdout or "0").strip() or "0")
            print(f"[purple-agent] {label} baseline: {n} lines")
            return n
        except Exception as e:
            print(f"[purple-agent] WARNING: failed to capture {label} baseline ({e}); will fall back to tail -c")
            return None
    _eve_before_lines = _capture_lines("/var/log/suricata/eve.json", "eve.json")
    _notice_before_lines = _capture_lines("/opt/zeek/logs/current/notice.log", "notice.log")
    _intel_before_lines = _capture_lines("/opt/zeek/logs/current/intel.log", "intel.log")

    # Probe source: either a curated YAML pool or pool-free taxonomy-only mode.
    probes_path = None
    if not args.pool_free:
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

    if args.pool_free:
        probe_source_section = POOL_FREE_SECTION
    else:
        probe_source_section = POOL_SECTION.format(probes_file=str(probes_path))

    system_prompt = SYSTEM_PROMPT.format(
        attacker_ip=args.attacker_ip,
        sensor_ip=args.sensor_ip,
        victim_ip=args.victim_ip,
        key_path=key_path,
        ssh_opts=ssh_opts,
        probe_source_section=probe_source_section,
        ledger_path=str(_ledger_path),
        max_turns=args.budget,
        max_attacks_str=(
            f"{args.max_attacks} (absolute hard cap)"
            if args.max_attacks is not None
            else "not set (no hard cap beyond turn budget)"
        ),
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

    if args.pool_free:
        kickoff = (
            "Begin the pool-free purple-team run. You have NO probe pool file. "
            "Improvise each probe from the attack taxonomy in your system prompt. "
            "AIM FOR VARIETY -- spread across 6+ categories, not just one. "
            "Iterate (baseline -> probe -> check -> record_finding) until you hit "
            "the turn budget, the attack cap, or run out of interesting ideas. "
            "Call record_finding for every attempt. Say 'PURPLE RUN COMPLETE' when done."
        )
    else:
        kickoff = (
            "Begin the purple-team run. First, use the Read tool to read the probe "
            "pool at the path given in your system prompt. Then iterate through "
            "candidates (baseline -> probe -> check -> record_finding) until you hit "
            "the turn budget or have nothing novel left to try. Focus on probes "
            "NOT already covered by the CI catalog. Call record_finding for every "
            "attempt. Say 'PURPLE RUN COMPLETE' when you're done."
        )
    # SSH failure guardrail — the agent has previously stalled by misinterpreting
    # a transient SSH blip as a host-down condition and waiting indefinitely on
    # ScheduleWakeup / Monitor. Both are outside the allowed tool surface.
    kickoff += (
        "\n\nSSH FAILURE HANDLING: if an SSH call to the Kali attacker or the "
        "sensor returns a transient error (timeout, connection refused, pipe "
        "broken, any non-zero exit), do NOT conclude the host is down. The lab "
        "does not reboot mid-run. Record the failing probe as verdict=ERROR "
        "with a one-line note and IMMEDIATELY move to the next probe. Do NOT "
        "use ScheduleWakeup, Monitor, ToolSearch, or any other wait/poll/"
        "discovery tool — your tool surface is strictly {Bash, Read, "
        "record_finding}. Staying within that surface is a hard requirement."
    )
    if args.focus:
        kickoff += f"\n\nADDITIONAL FOCUS FOR THIS RUN: {args.focus}"

    print(f"[purple-agent] starting run {ts}")
    print(f"[purple-agent] ledger:  {_ledger_path}")
    print(f"[purple-agent] budget:  {args.budget} turns")
    print(f"[purple-agent] mode:    {'pool-free (improvised)' if args.pool_free else 'pool-driven'}")
    if args.max_attacks is not None:
        print(f"[purple-agent] max-attacks cap: {args.max_attacks}")
    print(f"[purple-agent] lab:     atk={args.attacker_ip} sns={args.sensor_ip} vic={args.victim_ip}")
    print("=" * 72)

    turn = 0
    pushback_count = 0
    MAX_PUSHBACKS = 5
    last_count = 0  # progress guard: if a pushback adds zero new probes, bail
    try:
        async with ClaudeSDKClient(options=options) as client:
            current_query = kickoff
            while True:
                await client.query(current_query)
                said_complete = False
                async for message in client.receive_response():
                    if isinstance(message, AssistantMessage):
                        turn += 1
                        for block in message.content:
                            if isinstance(block, TextBlock):
                                text = block.text.strip()
                                if text:
                                    preview = text[:160].replace("\n", " ")
                                    print(f"[turn {turn:>2}] {preview}")
                                if "PURPLE RUN COMPLETE" in block.text.upper():
                                    said_complete = True
                            elif isinstance(block, ToolUseBlock):
                                inp_preview = str(block.input)[:120].replace("\n", " ")
                                print(f"[turn {turn:>2}] -> {block.name}({inp_preview}...)")

                # After the response ends, decide whether to push back or exit.
                # Push back if ledger < cap and pushback budget available, regardless of
                # whether the agent explicitly said PURPLE RUN COMPLETE. The old logic
                # only pushed back on the COMPLETE phrase; in practice the agent stalls
                # by emitting text-only responses (e.g., "I'll wait for monitor...") which
                # ends receive_response without the phrase. That dropped runs silently.
                if _max_attacks is None:
                    break  # no cap → whatever the agent did is final
                current_count = sum(
                    1 for line in _ledger_path.open(encoding="utf-8") if line.strip()
                ) if _ledger_path.exists() else 0
                if current_count >= _max_attacks:
                    break  # cap reached, legitimate
                # Progress guard: if the most recent pushback added zero probes
                # (agent answered with text only, never called record_finding),
                # do not burn another slot -- terminate cleanly.
                if pushback_count > 0 and current_count == last_count:
                    print(
                        f"[purple-agent] cap not reached ({current_count}/{_max_attacks}); "
                        f"agent made no ledger progress on pushback — terminating."
                    )
                    break
                if pushback_count >= MAX_PUSHBACKS:
                    print(
                        f"[purple-agent] cap not reached ({current_count}/{_max_attacks}); "
                        f"pushback limit ({MAX_PUSHBACKS}) hit — terminating."
                    )
                    break
                pushback_count += 1
                last_count = current_count
                remaining = _max_attacks - current_count
                stop_reason = (
                    "said COMPLETE" if said_complete
                    else "stopped without COMPLETE (text-only response or budget)"
                )
                print(
                    f"[purple-agent] agent {stop_reason} at {current_count}/{_max_attacks} -- "
                    f"pushing back (attempt {pushback_count}/{MAX_PUSHBACKS}, "
                    f"{remaining} slots remaining)"
                )
                current_query = (
                    f"REJECTED: the attack cap is NOT reached "
                    f"({current_count}/{_max_attacks} probes recorded, "
                    f"{remaining} slots remaining). Do NOT say PURPLE RUN COMPLETE. "
                    f"Continue running {remaining} MORE probes. "
                    f"\n\n"
                    f"CRITICAL: if an SSH call to the Kali attacker or the sensor "
                    f"returns a transient error (timeout, connection refused, pipe "
                    f"broken), do NOT conclude the host is down. Kali does not reboot. "
                    f"Record the failing probe as verdict=ERROR with a brief note and "
                    f"IMMEDIATELY move to the next probe. Do NOT use ScheduleWakeup, "
                    f"Monitor, or any waiting/polling tool -- those are out of scope. "
                    f"Your only tools are Bash, Read, and record_finding. "
                    f"\n\n"
                    f"Pick from UNEXPLORED territory: tools you haven't used yet "
                    f"(feroxbuster, gobuster, wpscan, enum4linux, snmpwalk, ike-scan, "
                    f"nbtscan, smbmap, rpcinfo, showmount, wafw00f, httpx, whatweb), "
                    f"protocols you haven't touched (SMTP banner, FTP anonymous, LDAP "
                    f"anonymous, NTP mode-6, SIP, mqtt, amqp, rsync, NFS showmount, "
                    f"SNMPv1/v2c/v3, telnet), old CVEs (Apache CVE-2021-41773, "
                    f"Log4Shell, Shellshock, Heartbleed), and evasion variants "
                    f"(different ports, encodings, user-agents, timing). "
                    f"Start the next probe immediately."
                )
    except KeyboardInterrupt:
        print("\n[purple-agent] interrupted -- writing partial report")
    except Exception as e:
        print(f"\n[purple-agent] error: {type(e).__name__}: {e}")

    print("=" * 72)

    # End-of-run sensor sweep: Zeek's SumStats-based detections (Scan::Port_Scan,
    # SSH::Password_Guessing, etc.) aggregate over 2-minute buckets. Per-probe
    # checks can't see them because the bucket hasn't flushed. Wait out the
    # bucket window, then harvest every notice the sensor wrote during the run
    # window. Saved as a sidecar; rendered in its own report section.
    sweep_path = _end_of_run_zeek_sweep(args, ts)

    # Deterministic accuracy audit — cross-checks every ledger claim against
    # sensor ground truth (Suricata eve.json + Zeek notice.log). Runs on every
    # build; result is a JSON sidecar consumed by write_html_report.
    audit_path = _end_of_run_accuracy_audit(args, ts, _ledger_path)

    write_html_report(REPORTS_DIR, ts, _ledger_path, args, probes_yaml_path=probes_path, sweep_path=sweep_path, audit_path=audit_path)


def _end_of_run_zeek_sweep(args, ts):
    """Sleep for the SumStats bucket window, then harvest sensor notice.log.

    Returns the sidecar JSON path (or None on failure / --no-sweep).
    Keeps attribution loose -- doesn't try to map notices to probes;
    the report renders them as an aggregate view with timestamps.
    """
    if getattr(args, "no_sweep", False):
        return None
    sweep_wait = 180  # 3 min — covers SSH::guessing_timeout (2m) and Scan::scan_timeout (2m)
    print(f"[purple-agent] post-run sensor sweep: waiting {sweep_wait}s for Zeek SumStats buckets to flush...")
    import time
    time.sleep(sweep_wait)

    sweep_path = REPORTS_DIR / f"sweep-{ts}.json"
    # Derive the run-start epoch from ts ("20260421T211421Z").
    try:
        run_start = int(datetime.strptime(ts, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).timestamp())
    except Exception:
        run_start = 0
    window_sec = max(1, int(datetime.now(timezone.utc).timestamp() - run_start) + 60)

    key_path = args.key
    ssh_opts = (
        f"-i {key_path} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"
    )
    # One compound sensor query: notice.log + intel.log for the run window.
    # Tail forward from run-start line-count baselines where captured -- same
    # truncation fix as the accuracy audit uses.
    if _notice_before_lines is not None:
        notice_src = f"sudo tail -n +{_notice_before_lines + 1} /opt/zeek/logs/current/notice.log 2>/dev/null"
    else:
        notice_src = "sudo tail -c 2000000 /opt/zeek/logs/current/notice.log 2>/dev/null"
    if _intel_before_lines is not None:
        intel_src = f"sudo tail -n +{_intel_before_lines + 1} /opt/zeek/logs/current/intel.log 2>/dev/null"
    else:
        intel_src = "sudo tail -c 500000 /opt/zeek/logs/current/intel.log 2>/dev/null"
    remote_cmd = (
        f"echo '=== NOTICES ==='; "
        f"{notice_src} "
        f'| jq -c "select((.ts|tonumber) > (now - {window_sec})) | '
        f'{{ts, note, src: (.src // .\\"id.orig_h\\"), dst: .\\"id.resp_h\\", msg: (.msg // \\"\\"), sub: (.sub // \\"\\")}}"'
        f" 2>/dev/null; "
        f"echo '=== INTEL ==='; "
        f"{intel_src} "
        f'| jq -c "select((.ts|tonumber) > (now - {window_sec})) | '
        f'{{ts, indicator: .\\"seen.indicator\\", type: .\\"seen.indicator_type\\", src: (.src // .\\"id.orig_h\\"), dst: .\\"id.resp_h\\", source: .sources[0]}}"'
        f" 2>/dev/null"
    )
    import subprocess, shlex
    try:
        result = subprocess.run(
            ["bash", "-c", f"ssh {ssh_opts} ubuntu@{args.sensor_ip} {shlex.quote(remote_cmd)}"],
            capture_output=True, text=True, timeout=60,
        )
        raw = result.stdout
    except Exception as e:
        print(f"[purple-agent] sweep ssh failed: {e}")
        return None

    notices, intel = [], []
    section = None
    for line in raw.splitlines():
        line = line.strip()
        if line == "=== NOTICES ===":
            section = "n"; continue
        if line == "=== INTEL ===":
            section = "i"; continue
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if section == "n":
            notices.append(entry)
        elif section == "i":
            intel.append(entry)

    sweep = {"run_start_epoch": run_start, "window_sec": window_sec, "notices": notices, "intel_hits": intel}
    sweep_path.write_text(json.dumps(sweep, indent=2), encoding="utf-8")
    print(f"[purple-agent] sweep written: {sweep_path} ({len(notices)} notices, {len(intel)} intel hits)")
    return sweep_path


def _end_of_run_accuracy_audit(args, ts, ledger_path):
    """Deterministic accuracy audit of the ledger vs sensor ground truth.

    Runs automatically on every report generation. Cross-checks:
      - Suricata SIDs claimed in each probe vs what actually fired in eve.json
        within a ±60s window of the probe's timestamp
      - Zeek notices claimed vs actual notice.log entries
      - Known structural anomalies (duplicate probe names, missing required fields,
        confidence auto-corrections, FP flag consistency)

    Output: reports/accuracy-{ts}.json sidecar. Consumed by
    _build_accuracy_audit_section(). Runs in parallel with report assembly —
    the orchestrator calls this right after the sweep, and write_html_report
    loads the result.
    """
    import subprocess, shlex, time as _time
    audit_path = REPORTS_DIR / f"accuracy-{ts}.json"

    # Load ledger first
    try:
        with open(ledger_path, encoding="utf-8") as f:
            ledger = [json.loads(line) for line in f if line.strip()]
    except Exception as e:
        print(f"[purple-agent] accuracy audit: ledger unreadable: {e}")
        return None
    if not ledger:
        print("[purple-agent] accuracy audit: empty ledger; skipping")
        return None

    # Derive the run window from ledger timestamps.
    try:
        run_start = int(datetime.strptime(ts, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc).timestamp())
    except Exception:
        run_start = 0
    if run_start == 0:
        # Without a valid run_start, the ts-based window filter can't tell run
        # alerts from historical noise. Refuse to produce a misleading audit.
        print("[purple-agent] accuracy audit: bad run_start (ts parse failed); skipping")
        return None
    window_sec = max(60, int(_time.time() - run_start) + 60)

    key_path = args.key
    ssh_opts = (
        f"-i {key_path} -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10"
    )
    # Compound sensor query: every alert + notice since the run started.
    # Tail FORWARD from line-count baselines captured at run start; falls back
    # to a large byte-count tail with sed '1d' to drop the partial first line
    # when baselines weren't captured. (Python filters by timestamp after
    # pulling; jq's fromdate/fromdateiso8601 can't parse Suricata's
    # microsecond+tz format.)
    if _eve_before_lines is not None:
        alert_src = f"sudo tail -n +{_eve_before_lines + 1} /var/log/suricata/eve.json 2>/dev/null"
    else:
        alert_src = "sudo tail -c 50000000 /var/log/suricata/eve.json 2>/dev/null | sed '1d'"
    if _notice_before_lines is not None:
        notice_src = f"sudo tail -n +{_notice_before_lines + 1} /opt/zeek/logs/current/notice.log 2>/dev/null"
    else:
        notice_src = "sudo tail -c 2000000 /opt/zeek/logs/current/notice.log 2>/dev/null | sed '1d'"
    remote_cmd = (
        f"echo '=== ALERTS ==='; "
        f"{alert_src} "
        f'| jq -c "select(.event_type == \\"alert\\") | '
        f'{{ts: .timestamp, sid: .alert.signature_id, sig: .alert.signature, '
        f'src: .src_ip, dst: .dest_ip}}"'
        f" 2>/dev/null; "
        f"echo '=== NOTICES ==='; "
        f"{notice_src} "
        f'| jq -c "select((.ts|tonumber) > (now - {window_sec})) | '
        f'{{ts, note, src: (.src // .\\"id.orig_h\\")}}"'
        f" 2>/dev/null"
    )
    try:
        result = subprocess.run(
            ["bash", "-c", f"ssh {ssh_opts} ubuntu@{args.sensor_ip} {shlex.quote(remote_cmd)}"],
            capture_output=True, text=True, timeout=90,
        )
        raw = result.stdout
    except Exception as e:
        print(f"[purple-agent] accuracy audit ssh failed: {e}")
        return None

    sensor_alerts, sensor_notices = [], []
    section = None
    for line in raw.splitlines():
        line = line.strip()
        if line == "=== ALERTS ===":
            section = "a"; continue
        if line == "=== NOTICES ===":
            section = "n"; continue
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
        if section == "a":
            sensor_alerts.append(entry)
        elif section == "n":
            sensor_notices.append(entry)

    # Index sensor alerts by SID with timestamp list for ±60s window comparison.
    sid_timestamps = {}
    for a in sensor_alerts:
        sid = str(a.get("sid", ""))
        ts_raw = a.get("ts", "")
        # Suricata timestamps look like "2026-04-21T23:58:37.123456+0000".
        # Python 3.11+ fromisoformat accepts compact tz "+HHMM", older versions
        # need "+HH:MM". Normalize the trailing tz so it's colon-separated.
        ts_normalized = ts_raw.replace("Z", "+00:00")
        if len(ts_normalized) >= 5 and ts_normalized[-5] in ("+", "-") and ":" not in ts_normalized[-5:]:
            ts_normalized = ts_normalized[:-2] + ":" + ts_normalized[-2:]
        try:
            ts_epoch = datetime.fromisoformat(ts_normalized).timestamp() if ts_normalized else 0
        except Exception:
            ts_epoch = 0
        # Only keep alerts from run_start forward. The per-probe ±60s match
        # below handles forward drift; opening this floor lets historical
        # alerts leak in and falsely "verify" claims.
        if ts_epoch and ts_epoch >= run_start:
            sid_timestamps.setdefault(sid, []).append(ts_epoch)

    # Cross-check each ledger entry.
    probe_audits = []
    overclaim_count = 0
    underclaim_count = 0
    structural_issues = []
    seen_probes = set()

    for entry in ledger:
        probe = entry.get("probe", "")
        if not probe:
            structural_issues.append({"issue": "missing probe_name", "entry_ts": entry.get("ts", "")})
            continue
        if probe in seen_probes:
            structural_issues.append({"issue": "duplicate probe name", "probe": probe})
        seen_probes.add(probe)

        # DETECTED verdict is only valid if the agent recorded SOME evidence:
        # a Suricata SID, a Zeek notice, or a populated zeek_signals line.
        verdict = entry.get("verdict", "")
        if verdict == "DETECTED":
            has_sid = bool(entry.get("fired_sids", []))
            has_notice = bool(entry.get("zeek_notices", []))
            zsig = entry.get("zeek_signals", "") or ""
            has_zsig = bool(zsig) and zsig.lower().strip() not in ("empty", "none", "")
            if not (has_sid or has_notice or has_zsig):
                structural_issues.append({
                    "issue": "DETECTED with no evidence (no fired_sids, no zeek_notices, no zeek_signals)",
                    "probe": probe,
                })

        claimed_sids = entry.get("fired_sids", []) or []
        try:
            probe_ts = datetime.fromisoformat(entry.get("ts", "").replace("Z", "+00:00")).timestamp()
        except Exception:
            probe_ts = 0

        # For each claimed SID, verify it fired within ±60s of the probe's ts.
        verified_sids = []
        unverified_sids = []
        if probe_ts:
            for sid in claimed_sids:
                firings = sid_timestamps.get(str(sid), [])
                match = any(abs(t - probe_ts) <= 60 for t in firings)
                (verified_sids if match else unverified_sids).append(sid)

        if unverified_sids:
            overclaim_count += 1

        probe_audits.append({
            "probe": probe,
            "ts": entry.get("ts", ""),
            "verdict": entry.get("verdict", ""),
            "claimed_sids": claimed_sids,
            "verified_sids": verified_sids,
            "unverified_sids": unverified_sids,
        })

    # Aggregate counts
    total_probes = len(ledger)
    verdicts = {}
    for e in ledger:
        v = e.get("verdict", "?")
        verdicts[v] = verdicts.get(v, 0) + 1

    audit = {
        "run_start_epoch": run_start,
        "window_sec": window_sec,
        "total_probes": total_probes,
        "verdict_distribution": verdicts,
        "sensor_alerts_in_window": len(sensor_alerts),
        "sensor_unique_sids": len({str(a.get("sid", "")) for a in sensor_alerts}),
        "sensor_notices_in_window": len(sensor_notices),
        "structural_issues": structural_issues,
        "overclaim_count": overclaim_count,
        "probe_audits": probe_audits,
    }
    audit_path.write_text(json.dumps(audit, indent=2), encoding="utf-8")
    print(
        f"[purple-agent] accuracy audit written: {audit_path} "
        f"({total_probes} probes, {overclaim_count} overclaims, "
        f"{len(structural_issues)} structural issues)"
    )
    return audit_path


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


def _normalize_confidence(claimed, fired_sids, zeek_notices):
    """Return (confidence, was_corrected) so callers can flag inflated claims.

    Rules:
      - high/partial require a Suricata SID (fired_sids non-empty)
      - behavioral requires a Zeek notice/weird entry (zeek_notices non-empty)
      - any violation is downgraded to "none"
    Applied in both record_finding (write-time) and _enrich_findings (read-time)
    so old ledgers regenerate clean.
    """
    c = (claimed or "").lower()
    if c in ("high", "partial") and not fired_sids:
        return "none", True
    if c == "behavioral" and not zeek_notices:
        return "none", True
    return c, False


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

        # Split zeek_notices/zeek_weird using the namespace heuristic:
        # notice.log events are Module::Event; weird.log names have no "::".
        # Run unconditionally so that even if the agent mis-classifies ONE weird
        # name into zeek_notices while correctly populating zeek_weird, we still
        # migrate the mis-placed entry. Also handles old pre-split ledgers.
        raw_notices = e.get("zeek_notices", []) or []
        raw_weird = e.get("zeek_weird", []) or []
        real_notices = [n for n in raw_notices if "::" in n]
        misplaced_weird = [n for n in raw_notices if "::" not in n]
        e["zeek_notices"] = real_notices
        e["zeek_weird"] = list(raw_weird) + misplaced_weird

        # Older runs encoded weird.log entries inside the free-text zeek_signals
        # field (e.g. "weird.log: data_before_established, inappropriate_FIN --
        # ...") instead of the structured zeek_weird list. Extract those so they
        # get counted as weird anomalies on regeneration.
        if not e["zeek_weird"] and e.get("zeek_signals"):
            m = re.search(r"weird\.log:\s*([^|]+?)(?:\s*--|\s*\||\s*$)", e["zeek_signals"], re.I)
            if m:
                tokens = [t.strip() for t in re.split(r"[,;]", m.group(1)) if t.strip()]
                # keep only identifier-shaped tokens (weird names are snake_case)
                extracted = [t for t in tokens if re.match(r"^[A-Za-z][A-Za-z0-9_%]{2,}$", t)]
                if extracted:
                    e["zeek_weird"] = extracted

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

        # Confidence: prefer finding, fallback to inference, then normalize
        # against hard evidence so old ledgers with inflated "behavioral" values
        # regenerate into honest reports.
        confidence = e.get("confidence", "")
        if not confidence:
            if verdict == "DETECTED" and not fp_flag:
                confidence = "high"
            else:
                confidence = "none"
        confidence, was_corrected = _normalize_confidence(
            confidence, e.get("fired_sids", []), e.get("zeek_notices", [])
        )
        e["confidence"] = confidence
        if was_corrected and not e.get("claimed_confidence"):
            e["claimed_confidence"] = f.get("confidence", "")

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
    .summary-text p { margin: 0 0 0.9rem 0; line-height: 1.6; }
    .summary-text p:last-child { margin-bottom: 0; }
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


_NEGATIVE_SIGNAL_RE = re.compile(
    r"^\s*(no\b|none\b|n/a\b|nothing\b|empty\b|tcp/\d+ refused|connection refused)",
    re.I,
)


def _has_zeek_visibility(f):
    """True iff zeek_signals describes actual observed traffic.

    The agent sometimes records absence assertions ("No Kerberos log entries --
    TCP/88 refused at SYN") in zeek_signals. A naive bool(str) check reads those
    as presence. Strip leading whitespace and reject if the string starts with a
    negative-assertion pattern.
    """
    sigs = (f.get("zeek_signals") or "").strip()
    if not sigs:
        return False
    return not _NEGATIVE_SIGNAL_RE.match(sigs)


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
        has_zeek_visibility = _has_zeek_visibility(f)
        if has_suricata:
            suricata_alert.append(f)
        elif has_zeek_alert:
            zeek_alert_only.append(f)
        elif has_zeek_visibility:
            visibility_only.append(f)
        else:
            no_visibility.append(f)
    return suricata_alert, zeek_alert_only, visibility_only, no_visibility


def _build_exec_summary(enriched, buckets, sweep_data=None):
    total = len(enriched)
    n_error = len(buckets.get("ERROR", []))
    n_fp = sum(1 for f in enriched if f.get("fp"))

    suricata_alert, zeek_alert_only, visibility_only, no_visibility = _classify_by_layer(enriched)
    n_suri = len(suricata_alert)
    n_zeek_only = len(zeek_alert_only)
    n_vis = len(visibility_only)
    n_blind = len(no_visibility)
    n_undetected = n_vis + n_blind

    # Total Zeek notice.log alerts = probes with non-empty zeek_notices,
    # regardless of Suricata overlap. weird.log is counted separately.
    n_zeek_total = sum(1 for f in enriched if f.get("zeek_notices"))
    n_weird_total = sum(1 for f in enriched if f.get("zeek_weird"))
    n_both_layers = sum(
        1 for f in enriched if f.get("zeek_notices") and f.get("fired_sids")
    )

    suri_pct = f"{100 * n_suri / total:.0f}" if total > 0 else "0"
    zeek_pct = f"{100 * n_zeek_total / total:.0f}" if total > 0 else "0"
    # Overall = union of Suricata SIDs and Zeek notices (either layer alerted)
    overall_pct = f"{100 * (n_suri + n_zeek_only) / total:.0f}" if total > 0 else "0"
    undetected_pct = f"{100 * n_undetected / total:.0f}" if total > 0 else "0"

    # Count unique SIDs fired
    unique_sids = set()
    for f in suricata_alert:
        for sid in f.get("fired_sids", []):
            unique_sids.add(sid)

    # Undetected breakdown by tactic -- exclude ERROR probes (probe didn't run ≠
    # detection gap) and FP probes (rule-accuracy issue ≠ detection gap).
    undetected = [
        f for f in (visibility_only + no_visibility)
        if f.get("verdict") != "ERROR" and not f.get("fp")
    ]
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

    # Real undetected count for exec summary (excludes ERROR + FP)
    n_true_undetected = len(undetected)
    true_undetected_pct = (
        f"{100 * n_true_undetected / total:.0f}" if total > 0 else "0"
    )

    tools = set(f.get("tool_used", "") for f in enriched if f.get("tool_used"))

    # Visibility/blind-spot breakdown should mirror the true-undetected slice,
    # not lump ERROR/FP probes in with real gaps.
    vis_true = [f for f in visibility_only if f.get("verdict") != "ERROR" and not f.get("fp")]
    blind_true = [f for f in no_visibility if f.get("verdict") != "ERROR" and not f.get("fp")]

    def _s(n):  # plural helper
        return "" if n == 1 else "s"

    # Paragraph 1: plain-language methodology
    para_methodology = (
        f"A purple-team agent ran <strong>{total} simulated attack{_s(total)}</strong> "
        f"against this lab's sensor stack. For each one, the agent baselined Suricata and "
        f"Zeek, executed the attack from a Kali attacker box against the victim, diffed the "
        f"resulting logs, recorded the outcome, and moved to the next attack."
    )

    # Paragraph 2: detection picture (Suricata + Zeek always surfaced, even at 0)
    para_detection = (
        f"Of the {total} attack{_s(total)}, "
        f"<strong>Suricata caught {n_suri} ({suri_pct}% detection rate)</strong> "
        f"matching {len(unique_sids)} unique rule ID{_s(len(unique_sids))}. "
        f"<strong>Zeek's notice.log fired on {n_zeek_total}.</strong> "
    )
    if n_true_undetected > 0:
        para_detection += (
            f"The remaining <strong>{n_true_undetected} attack{_s(n_true_undetected)} "
            f"({true_undetected_pct}%) produced no alert on either layer.</strong> "
        )
        if vis_true and blind_true:
            para_detection += (
                f"Zeek's protocol logs captured the traffic for {len(vis_true)} of them — "
                f"candidates for writing new Suricata rules from observed metadata — and "
                f"{len(blind_true)} attack{_s(len(blind_true))} left no sensor evidence at all."
            )
        elif vis_true:
            para_detection += (
                f"Zeek's protocol logs captured the traffic for all {len(vis_true)} — "
                f"candidates for writing new Suricata rules from observed metadata."
            )
        elif blind_true:
            para_detection += (
                f"{len(blind_true)} attack{_s(len(blind_true))} left no sensor evidence at all."
            )
    if n_weird_total > 0:
        para_detection += (
            f" Zeek's weird.log flagged protocol-parser anomalies on {n_weird_total} "
            f"attack{_s(n_weird_total)} (hunting-grade signal, not a direct alert)."
        )

    # Paragraph 3: severity + cluster
    para_severity_parts = []
    if crit_gaps > 0:
        para_severity_parts.append(
            f"<strong>{crit_gaps} {'is' if crit_gaps == 1 else 'are'} Critical</strong> "
            f"(initial-access or code-execution techniques that would let an adversary "
            f"establish a foothold)"
        )
    if high_gaps > 0:
        para_severity_parts.append(
            f"<strong>{high_gaps} {'is' if high_gaps == 1 else 'are'} High</strong> "
            f"(undetected C2, credential theft, or data exfiltration)"
        )
    para_severity = ""
    if para_severity_parts and n_true_undetected > 0:
        para_severity = (
            f"Of the {n_true_undetected} undetected attack{_s(n_true_undetected)}, "
            + " and ".join(para_severity_parts) + ". "
        )
    if kev_gaps > 0:
        para_severity += (
            f"<strong>{kev_gaps} undetected attack{_s(kev_gaps)} target CISA Known Exploited "
            f"Vulnerabilities</strong>, indicating active real-world exploitation with no "
            f"sensor coverage. "
        )
    if gap_tactics:
        top_count = gap_tactics[top_gap_tactic]
        para_severity += (
            f"Gaps cluster most heavily in the <strong>{_esc(top_gap_tactic)}</strong> "
            f"tactic ({top_count} of {n_true_undetected})."
        )

    # Assemble with explicit paragraph breaks. Context: {narrative} gets wrapped
    # in <p>...</p> by the summary-text div, so internal paragraph boundaries
    # need </p><p> markers. Sweep data is deliberately kept out of the exec
    # summary — it has its own dedicated section below and mixing it in muddles
    # per-attack attribution.
    narrative = para_methodology
    if para_detection:
        narrative += "</p><p>" + para_detection
    if para_severity:
        narrative += "</p><p>" + para_severity

    footer_notes = []
    if n_error > 0:
        footer_notes.append(
            f"{n_error} attack{_s(n_error)} failed to execute "
            f"(tool missing, timeout, connection refused)"
        )
    if n_fp > 0:
        footer_notes.append(
            f"{n_fp} detection{_s(n_fp)} {'was' if n_fp == 1 else 'were'} "
            f"false positive{_s(n_fp)} (unrelated signature fired)"
        )
    footer_html = ""
    if footer_notes:
        footer_html = '<p style="font-size:0.85rem; color:#666; margin-top:0.8rem;">' + ". ".join(footer_notes) + ".</p>"

    return f"""
    <h2>Executive Summary</h2>
    <div class="stat-boxes">
        <div class="stat-box" style="background:#1a1a2e;"><div class="num">{total}</div><div class="label">Attacks Conducted</div></div>
        <div class="stat-box stat-promote"><div class="num">{n_suri}</div><div class="label">Suricata Alerts</div></div>
        <div class="stat-box" style="background:#17a2b8;"><div class="num">{n_zeek_total}</div><div class="label" title="Probes where Zeek notice.log fired during per-probe check. Attributed to specific attacks.">Zeek Alerts</div></div>
        <div class="stat-box stat-gap"><div class="num">{n_true_undetected}</div><div class="label" title="Probes with no Suricata SID and no Zeek notice. Excludes ERROR and FP probes.">No Detection</div></div>
    </div>
    <div class="detection-rates">
        <div class="rate-item">
            <div class="pct" style="color:#28a745;">{overall_pct}%</div>
            <div class="rlabel">Overall Detection Rate</div>
        </div>
        <div class="rate-item">
            <div class="pct" style="color:#28a745;">{suri_pct}%</div>
            <div class="rlabel">Suricata Detection Rate</div>
        </div>
        <div class="rate-item">
            <div class="pct" style="color:#17a2b8;">{zeek_pct}%</div>
            <div class="rlabel">Zeek Detection Rate</div>
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
    display_verdict = verdict
    if f.get("fp"):
        badge_class = "badge-fp"
        display_verdict = "FP"
    severity = f.get("severity", "Info")
    sev_color = SEVERITY_COLORS.get(severity, "#6c757d")

    # Confidence + KEV badges
    confidence = f.get("confidence", "")
    conf_color = CONFIDENCE_COLORS.get(confidence, "#6c757d")
    kev_badge = ' <span class="badge" style="background:#7b2d8e;">CISA KEV</span>' if f.get("kev") else ""

    # Header
    header = f"""
    <div class="finding-header" style="border-left: 5px solid {sev_color};">
        <span class="badge {badge_class}">{_esc(display_verdict)}</span>
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


def _build_accuracy_audit_section(audit_data):
    """Render the inline accuracy-audit results produced by _end_of_run_accuracy_audit.

    Always rendered at the bottom of the report. Shows:
      - Per-probe SID verification (claimed vs sensor ground truth within ±60s)
      - Over-claim count (probes where claimed SIDs did NOT fire in the window)
      - Structural integrity issues (duplicates, missing fields)
      - Aggregate sensor stats for the run window
    """
    if not audit_data:
        return (
            '<h2>Accuracy Audit</h2>'
            '<p><em>Audit skipped or sensor unreachable. Rerun with sensor access to '
            'cross-check ledger claims against eve.json / notice.log ground truth.</em></p>'
        )

    probe_audits = audit_data.get("probe_audits", []) or []
    overclaim = audit_data.get("overclaim_count", 0)
    structural = audit_data.get("structural_issues", []) or []
    total = audit_data.get("total_probes", 0)
    sensor_alerts = audit_data.get("sensor_alerts_in_window", 0)
    sensor_sids = audit_data.get("sensor_unique_sids", 0)
    sensor_notices = audit_data.get("sensor_notices_in_window", 0)

    # Overclaim rate -- denominator is probes-with-claims, not total probes.
    # UNDETECTED/ERROR probes have no fired_sids and can't logically overclaim;
    # including them in the denominator dilutes the rate and understates the
    # problem for runs with many ambient-gap probes.
    claimants = sum(1 for p in probe_audits if p.get("claimed_sids"))
    overclaim_pct = f"{100 * overclaim / claimants:.0f}" if claimants > 0 else "0"

    parts = [
        '<h2>Accuracy Audit</h2>',
        '<p>Deterministic cross-check of ledger claims against sensor ground truth '
        '(Suricata <code>eve.json</code> + Zeek <code>notice.log</code>). '
        'For each probe, claimed SIDs are verified to have fired within ±60s of '
        'the probe timestamp. Runs automatically on every build.</p>',
    ]

    # Stat boxes for the audit
    parts.append(f"""
    <div class="stat-boxes">
        <div class="stat-box" style="background:#1a1a2e;"><div class="num">{total}</div><div class="label">Probes Audited</div></div>
        <div class="stat-box stat-promote"><div class="num">{total - overclaim - len(structural)}</div><div class="label" title="Probes with no structural issues and no SID over-claims">Clean Entries</div></div>
        <div class="stat-box" style="background:#fd7e14;"><div class="num">{overclaim}</div><div class="label" title="Probes that claim Suricata SIDs that did not actually fire within ±60s of the probe timestamp on the sensor">SID Over-claims</div></div>
        <div class="stat-box stat-gap"><div class="num">{len(structural)}</div><div class="label" title="Duplicate probe names, missing required fields, malformed rows">Structural Issues</div></div>
    </div>
    <div class="detection-rates">
        <div class="rate-item"><div class="pct" style="color:#dc3545;">{overclaim_pct}%</div><div class="rlabel">Over-claim Rate</div></div>
        <div class="rate-item"><div class="pct">{sensor_alerts}</div><div class="rlabel">Sensor Alerts (window)</div></div>
        <div class="rate-item"><div class="pct">{sensor_sids}</div><div class="rlabel">Unique SIDs (sensor)</div></div>
        <div class="rate-item"><div class="pct">{sensor_notices}</div><div class="rlabel">Zeek Notices (window)</div></div>
    </div>
    """)

    # Over-claim probes table (limit top 20 by most unverified SIDs)
    overclaim_rows = [p for p in probe_audits if p.get("unverified_sids")]
    if overclaim_rows:
        overclaim_rows.sort(key=lambda p: -len(p.get("unverified_sids", [])))
        parts.append('<h3>Probes with unverified SID claims</h3>')
        parts.append(
            '<p style="font-size:0.85rem; color:#495057;">'
            'Ledger claims these SIDs fired but no matching alert appears in '
            '<code>eve.json</code> within ±60s of the probe timestamp. Causes include '
            'ambient canary SIDs (2001219 fires on ambient SSH, attributed to wrong '
            'probe), timestamp skew, or rule-engine rate-limiting.</p>'
        )
        parts.append(
            '<table class="gap-table" style="border-left:3px solid #fd7e14;">'
            '<thead><tr style="background:#fd7e14; color:#212529;">'
            '<th>Probe</th><th>Verdict</th><th>Verified SIDs</th>'
            '<th>Unverified SIDs</th><th>Probe ts</th>'
            '</tr></thead><tbody>'
        )
        for p in overclaim_rows[:20]:
            parts.append(
                f'<tr>'
                f'<td><strong>{_esc(p.get("probe",""))}</strong></td>'
                f'<td>{_esc(p.get("verdict",""))}</td>'
                f'<td style="font-family:monospace; font-size:0.8rem;">{_esc(", ".join(p.get("verified_sids", [])) or "—")}</td>'
                f'<td style="font-family:monospace; font-size:0.8rem; color:#dc3545;">{_esc(", ".join(p.get("unverified_sids", [])))}</td>'
                f'<td style="font-family:monospace; font-size:0.75rem;">{_esc(p.get("ts","")[:19])}</td>'
                f'</tr>'
            )
        parts.append('</tbody></table>')

    # Structural issues
    if structural:
        parts.append('<h3>Structural issues</h3>')
        parts.append('<ul style="margin:0.5rem 0;">')
        for issue in structural[:20]:
            parts.append(
                f'<li>{_esc(issue.get("issue",""))}'
                f'{" — " + _esc(issue.get("probe","") or issue.get("entry_ts","")) if issue.get("probe") or issue.get("entry_ts") else ""}'
                f'</li>'
            )
        parts.append('</ul>')

    if not overclaim_rows and not structural:
        parts.append(
            '<p style="color:#28a745; font-weight:600;">'
            '✓ All ledger claims verified against sensor ground truth. No over-claims or '
            'structural issues detected.</p>'
        )

    return "\n".join(parts)


def _build_sweep_section(sweep_data):
    """Render the end-of-run Zeek sensor sweep.

    The per-probe CHECK step can't see Zeek notices that fire on SumStats
    buckets (Scan::Port_Scan, SSH::Password_Guessing) because those aggregate
    over 2-minute windows. After the probe loop ends, the runner sleeps 3 min
    and dumps every notice/intel entry from the run window. Rendered here as
    an aggregate table -- we deliberately do NOT attribute notices to
    specific probes to avoid muddling per-probe ledger accuracy.
    """
    if not sweep_data:
        return '<h2>Zeek Sensor Sweep (post-run)</h2><p><em>Sweep skipped or sensor unreachable.</em></p>'

    notices = sweep_data.get("notices", [])
    intel_hits = sweep_data.get("intel_hits", [])

    parts = ['<h2>Zeek Sensor Sweep (post-run)</h2>']
    parts.append(
        '<p>Aggregated Zeek notice.log and intel.log entries captured ~3 minutes '
        'after the probe loop ended, so SumStats-based detections '
        '(<code>Scan::Port_Scan</code>, <code>SSH::Password_Guessing</code>) have '
        'time to flush. These entries may span multiple probes -- attribution to '
        'individual findings is intentionally not performed here.</p>'
    )

    if not notices and not intel_hits:
        parts.append('<p><em>No notices or intel hits during the run window.</em></p>')
        return "\n".join(parts)

    # Notice table
    if notices:
        note_counts = {}
        for n in notices:
            k = n.get("note", "?")
            note_counts[k] = note_counts.get(k, 0) + 1
        parts.append(f'<h3>Notices — {len(notices)} entries, {len(note_counts)} distinct types</h3>')
        parts.append('<table class="gap-table" style="border-left:3px solid #17a2b8;">'
                     '<thead><tr style="background:#17a2b8;">'
                     '<th>Count</th><th>Note</th><th>Sources</th>'
                     '</tr></thead><tbody>')
        for note, count in sorted(note_counts.items(), key=lambda x: -x[1]):
            srcs = set()
            for n in notices:
                if n.get("note") == note and n.get("src"):
                    srcs.add(n["src"])
            parts.append(
                f'<tr><td><strong>{count}</strong></td>'
                f'<td><code>{_esc(note)}</code></td>'
                f'<td>{_esc(", ".join(sorted(srcs)[:5]))}</td></tr>'
            )
        parts.append('</tbody></table>')

    # Intel framework hits
    if intel_hits:
        parts.append(f'<h3>Intel Framework hits — {len(intel_hits)}</h3>')
        parts.append('<p>Indicators from <code>/opt/zeek/intel/intel.dat</code> (Abuse.ch URLhaus / ThreatFox / Feodo / SSLBL) that matched observed traffic.</p>')
        parts.append('<table class="gap-table" style="border-left:3px solid #28a745;">'
                     '<thead><tr style="background:#28a745;">'
                     '<th>Indicator</th><th>Type</th><th>Feed</th><th>Destination</th>'
                     '</tr></thead><tbody>')
        for hit in intel_hits[:50]:
            parts.append(
                f'<tr><td><code>{_esc(hit.get("indicator", ""))}</code></td>'
                f'<td>{_esc(hit.get("type", ""))}</td>'
                f'<td>{_esc(hit.get("source", ""))}</td>'
                f'<td>{_esc(hit.get("dst", ""))}</td></tr>'
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

    <h3>Known Limitations</h3>
    <ul style="font-size:0.9rem; color:#495057; margin: 0.5rem 1rem;">
        <li><strong>Pool-free mode accuracy:</strong> when <code>--pool-free</code> is set, the agent
            improvises every probe from a TTP taxonomy rather than reading <code>probes.yaml</code>.
            MITRE IDs, tool labels, and categories are LLM-reported, not pool-validated. A small fraction
            of entries may have missing or inconsistent fields that render as "Unknown" in the matrix.
            For reproducible runs, prefer pool-driven mode.</li>
        <li><strong>Zeek flush latency:</strong> Zeek's ASCII log writer buffers entries ~1-2s before
            flushing. Fast probes (curl --max-time 5) may complete before Zeek writes to disk; the
            agent inserts a 2s sleep between probe and check to mitigate this.</li>
        <li><strong>Service-absent probes:</strong> probes targeting services not present on the victim
            (e.g. SMB/AD probes against a plain Ubuntu host) may classify as UNDETECTED due to TCP RST
            rather than a genuine detection gap -- a "no service" outcome, not a "missing rule" outcome.</li>
        <li><strong>Ambient SIDs:</strong> Suricata SIDs 9000003 (TCP SYN-scan canary) and 2001219
            (ET SCAN Potential SSH Scan) fire on ambient lab traffic. They are retained in
            <code>fired_sids</code> but only count toward DETECTED when the probe is itself a scanning
            technique.</li>
    </ul>

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

    # Expand sub-technique rows by default so parent techniques with sub-tech
    # children (e.g. T1078 + T1078.004) render with the sub-tech cells visible
    # in Navigator instead of collapsed under the parent badge.
    parents_with_subtechs = {tid.split(".")[0] for tid in technique_map if "." in tid}
    for entry in techniques:
        tid = entry["techniqueID"]
        if tid in parents_with_subtechs or "." in tid:
            entry["showSubtechniques"] = True

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


def write_html_report(reports_dir, ts, ledger_path, args, probes_yaml_path=None, sweep_path=None, audit_path=None):
    findings = _load_findings(ledger_path)
    enriched = _enrich_findings(findings, probes_yaml_path)

    sweep_data = None
    if sweep_path and Path(sweep_path).exists():
        try:
            sweep_data = json.loads(Path(sweep_path).read_text(encoding="utf-8"))
        except Exception:
            sweep_data = None

    audit_data = None
    if audit_path and Path(audit_path).exists():
        try:
            audit_data = json.loads(Path(audit_path).read_text(encoding="utf-8"))
        except Exception:
            audit_data = None

    buckets = {"DETECTED": [], "UNDETECTED": [], "ERROR": [], "OTHER": []}
    for f in enriched:
        v = f.get("verdict", "").upper()
        buckets.get(v, buckets["OTHER"]).append(f)

    css = _build_css()
    cover = _build_cover(ts, args)
    exec_summary = _build_exec_summary(enriched, buckets, sweep_data=sweep_data)
    suricata_alerts = _build_suricata_alerts(enriched)
    mitre_matrix = _build_mitre_matrix(enriched)
    findings_html = _build_findings_section(enriched)
    # Gap analysis shows true undetected probes only — FPs (a SID fired, just on
    # the wrong thing) are a rule-accuracy issue, not a detection gap.
    gap_analysis = _build_gap_analysis(
        [f for f in buckets["UNDETECTED"] if not f.get("fp")]
    )
    sweep_section = _build_sweep_section(sweep_data)
    audit_section = _build_accuracy_audit_section(audit_data)
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
{sweep_section}
{mitre_matrix}
{findings_html}
{gap_analysis}
{audit_section}
{appendix}
</body>
</html>"""

    out = reports_dir / f"report-{ts}.html"
    out.write_text(html, encoding="utf-8")
    print(f"[purple-agent] report written: {out}")
    print(f"[purple-agent] findings:       {ledger_path}")

    # ATT&CK Navigator layer
    write_navigator_layer(reports_dir, ts, enriched)

    # Auto-open in default browser unless explicitly suppressed (e.g. CI, headless)
    if not os.environ.get("PURPLE_AGENT_NO_OPEN"):
        import webbrowser
        webbrowser.open(out.resolve().as_uri())


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
        "--max-attacks",
        type=int,
        default=None,
        help="Hard cap on attack count. record_finding refuses further calls once reached. "
             "Unlike --budget (turns), this is an absolute, enforced probe-count ceiling.",
    )
    p.add_argument(
        "--probe-pool",
        help="Path to probes.yaml (default: probes.yaml in script dir)",
    )
    p.add_argument(
        "--pool-free",
        action="store_true",
        help="Skip probes.yaml entirely; agent improvises every probe from a "
             "built-in TTP taxonomy. Trades reproducibility for per-run variety.",
    )
    p.add_argument(
        "--no-sweep",
        action="store_true",
        help="Skip the 3-minute end-of-run sensor sweep for aggregated "
             "SumStats notices (Scan, SSH brute). Useful for fast iteration.",
    )
    p.add_argument(
        "--focus",
        default="",
        help="Free-text steering hint appended to the kickoff message (e.g. "
             "'prioritize probes likely to trigger both Suricata and Zeek').",
    )
    return p.parse_args()


def main():
    args = parse_args()
    asyncio.run(run_agent(args))


if __name__ == "__main__":
    main()
