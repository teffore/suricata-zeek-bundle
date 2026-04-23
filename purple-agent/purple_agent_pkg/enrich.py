"""enrich.py — pure functions and constants for findings enrichment.

Extracted from purple_agent.py (refactor-split pass #1). No side effects,
no SDK imports — this module can be imported and unit-tested in isolation.

Contents:
  - MITRE ATT&CK lookup + tactic-to-severity table
  - Noise-floor / KEV / color / severity constants
  - Pure helpers:
      _normalize_confidence  -- downgrade inflated claims when evidence is absent
      _normalize_verdict     -- map legacy verdicts (PROMOTE/SKIP/GAP/FP)
      _infer_tool            -- best-effort tool name from a command string
      _has_zeek_visibility   -- reject absence-assertion strings in zeek_signals
  - Loaders:
      _load_findings         -- ledger JSONL reader
      _load_probes_yaml      -- probes.yaml dict keyed by name
      _enrich_findings       -- join findings + pool + MITRE details + severity
"""

import json
import re
from pathlib import Path


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
    "T1090.002": {"tactic": "Command and Control", "name": "Proxy: External Proxy", "url": "https://attack.mitre.org/techniques/T1090/002/"},
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
    "T1048.002": {"tactic": "Exfiltration", "name": "Exfiltration Over Alternative Protocol: Asymmetric Encrypted Non-C2", "url": "https://attack.mitre.org/techniques/T1048/002/"},
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
    "T1499.002": {"tactic": "Impact", "name": "Endpoint Denial of Service: Service Exhaustion Flood", "url": "https://attack.mitre.org/techniques/T1499/002/"},
    "T1499.003": {"tactic": "Impact", "name": "Endpoint Denial of Service: Application Exhaustion Flood", "url": "https://attack.mitre.org/techniques/T1499/003/"},
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
    "T1205.001": {"tactic": "Defense Evasion", "name": "Traffic Signaling: Port Knocking", "url": "https://attack.mitre.org/techniques/T1205/001/"},
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
#  Negative-assertion detector for zeek_signals
# ============================================================================

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


# ============================================================================
#  Pure normalization helpers
# ============================================================================

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


# ============================================================================
#  Loaders + enrichment
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
