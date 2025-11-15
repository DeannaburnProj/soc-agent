# dashboard.py — SOC Tier-1 Interactive Analyst Console
# Features: VT enrichment (IP/Domain/Hash), AI triage (strict schema), guardrails,
# approval workflow, auto-triage, sample packs, CSV upload, VT cache,
# and TOP "Human Oversight Dashboard" with counters + expandable lists + jump-to.

import os
import json
import re
import time
from typing import Dict, Any, List, Tuple
from functools import lru_cache  # NEW: in-process cache

import pandas as pd
import requests
import streamlit as st
from openai import OpenAI

# =========================
# CONFIG
# =========================
MODEL_NAME = "gpt-4o-mini"
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")
client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

# =========================
# VT Cache (reduce rate limits)
# =========================
VT_CACHE_PATH = "vt_cache.json"
if os.path.exists(VT_CACHE_PATH):
    try:
        with open(VT_CACHE_PATH, "r", encoding="utf-8") as f:
            VT_CACHE = json.load(f)
    except Exception:
        VT_CACHE = {}
else:
    VT_CACHE = {}

def save_vt_cache():
    try:
        with open(VT_CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(VT_CACHE, f)
    except Exception:
        pass

# =========================
# Sample Alerts (rich set)
# =========================
SAMPLE_ALERTS: List[Dict[str, Any]] = [
    {
        "alert_id": "001",
        "alert_name": "Suspicious PowerShell Execution",
        "hostname": "finance-pc",
        "ip": "10.0.0.15",
        "domain": "",
        "hash": "",
        "user": "svc_backup",
        "details": "PowerShell ran with encoded command"
    },
    {
        "alert_id": "002",
        "alert_name": "Multiple Failed Logins",
        "hostname": "hr-laptop",
        "ip": "10.0.0.23",
        "domain": "vpn-contoso.example",
        "hash": "",
        "user": "jdoe",
        "details": "5 failed RDP login attempts"
    },
    {
        "alert_id": "003",
        "alert_name": "Unusual Outbound Traffic",
        "hostname": "server-01",
        "ip": "192.168.1.50",
        "domain": "",
        "hash": "44d88612fea8a8f36de82e1278abb02f",  # eicar md5 example
        "user": "SYSTEM",
        "details": "Outbound connection to rare external IP"
    },
    {
        "alert_id": "004",
        "alert_name": "Beaconing to Rare Domain",
        "hostname": "eng-workstation-07",
        "ip": "10.0.0.41",
        "domain": "telemetry-update-sync.co",
        "hash": "",
        "user": "alice",
        "details": "Repeated HTTPS connections every 60s to uncommon domain"
    },
    {
        "alert_id": "005",
        "alert_name": "Suspicious Service Install",
        "hostname": "print-srv-02",
        "ip": "192.168.1.22",
        "domain": "",
        "hash": "9f2c4d57b2b84a9e9d5b3a7fa4b1a7f9",
        "user": "SYSTEM",
        "details": "New Windows service registered pointing to unknown EXE"
    },
    {
        "alert_id": "006",
        "alert_name": "DNS Tunneling Pattern",
        "hostname": "sales-laptop-03",
        "ip": "10.0.0.88",
        "domain": "a1b2c3d4e5.fwd.tunnel-example.net",
        "hash": "",
        "user": "brian",
        "details": "High volume of long/encoded-looking DNS queries"
    },
    {
        "alert_id": "007",
        "alert_name": "Suspicious OAuth Grant",
        "hostname": "n/a",
        "ip": "172.16.20.14",
        "domain": "apps-login-checker.com",
        "hash": "",
        "user": "carla",
        "details": "User granted mailbox read scope to unknown app"
    },
    {
        "alert_id": "008",
        "alert_name": "Credential Dump Tool Detected",
        "hostname": "it-admin-01",
        "ip": "10.0.0.5",
        "domain": "",
        "hash": "3c1f8f9d8b5c4a7a2f9e6d1c3b8a7f11",
        "user": "admin",
        "details": "EDR flagged process resembling credential dumping behavior"
    },
    {
        "alert_id": "009",
        "alert_name": "Suspicious Scheduled Task",
        "hostname": "acct-pc-12",
        "ip": "10.0.0.112",
        "domain": "",
        "hash": "",
        "user": "SYSTEM",
        "details": "New scheduled task set to run PowerShell download cradle hourly"
    },
    {
        "alert_id": "010",
        "alert_name": "Lateral Movement via SMB",
        "hostname": "corp-sql-01",
        "ip": "192.168.1.70",
        "domain": "",
        "hash": "b1946ac92492d2347c6235b4d2611184",
        "user": "svc_sql",
        "details": "Multiple admin shares accessed within a short window"
    },
    {
        "alert_id": "011",
        "alert_name": "Phishing Link Clicked",
        "hostname": "marketing-mac-02",
        "ip": "10.0.0.63",
        "domain": "secure-login-office365.com",
        "hash": "",
        "user": "dana",
        "details": "User clicked credential-harvesting lookalike link"
    },
    {
        "alert_id": "012",
        "alert_name": "Ransomware Note Dropped",
        "hostname": "fileshare-01",
        "ip": "172.16.30.9",
        "domain": "",
        "hash": "",
        "user": "SYSTEM",
        "details": "File named READ_ME.txt created in multiple directories"
    },
    {
        "alert_id": "013",
        "alert_name": "Untrusted Binary Execution",
        "hostname": "eng-workstation-11",
        "ip": "10.0.0.92",
        "domain": "",
        "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "user": "chris",
        "details": "Unsigned binary executed from user temp directory"
    },
    {
        "alert_id": "014",
        "alert_name": "Unusual Geo Login",
        "hostname": "n/a",
        "ip": "172.16.40.44",
        "domain": "auth-portal.example.com",
        "hash": "",
        "user": "emma",
        "details": "Login from unusual country followed by inbox rules change"
    },
    {
        "alert_id": "015",
        "alert_name": "Suspicious Parent-Child Process",
        "hostname": "design-pc-04",
        "ip": "10.0.0.121",
        "domain": "",
        "hash": "",
        "user": "frank",
        "details": "WINWORD.exe spawned powershell.exe with hidden window"
    },
    {
        "alert_id": "016",
        "alert_name": "Outbound to Known TOR Node",
        "hostname": "ops-laptop-09",
        "ip": "10.0.0.142",
        "domain": "",
        "hash": "",
        "user": "gina",
        "details": "Connection to IP in TOR exit list"
    },
    {
        "alert_id": "017",
        "alert_name": "Malicious Macro Execution",
        "hostname": "finance-pc-03",
        "ip": "10.0.0.33",
        "domain": "",
        "hash": "5d41402abc4b2a76b9719d911017c592",
        "user": "harry",
        "details": "Office doc macro created persistence with Run key"
    },
    {
        "alert_id": "018",
        "alert_name": "Cloud Storage Exfil",
        "hostname": "legal-pc-02",
        "ip": "192.168.1.105",
        "domain": "upload-sync-storage.com",
        "hash": "",
        "user": "irene",
        "details": "Large upload to rarely used cloud storage domain"
    },
    {
        "alert_id": "019",
        "alert_name": "Crypto Miner Behavior",
        "hostname": "render-node-07",
        "ip": "172.16.50.17",
        "domain": "",
        "hash": "6dcd4ce23d88e2ee9568ba546c007c63",
        "user": "SYSTEM",
        "details": "High CPU with outbound to mining pools"
    },
    {
        "alert_id": "020",
        "alert_name": "New Local Admin Created",
        "hostname": "helpdesk-pc-01",
        "ip": "10.0.0.18",
        "domain": "",
        "hash": "",
        "user": "helpdesk",
        "details": "Local admin group modified; unknown account added"
    }
]

# =========================
# VirusTotal enrichment helpers (IP/Domain/Hash)
# =========================
HASH_RE = re.compile(r"^[A-Fa-f0-9]{32}$|^[A-Fa-f0-9]{40}$|^[A-Fa-f0-9]{64}$")

def vt_headers() -> Dict[str, str]:
    return {"Accept": "application/json", "x-apikey": VT_API_KEY}

def cache_get(key: str):
    return VT_CACHE.get(key)

def cache_set(key: str, value: dict):
    VT_CACHE[key] = value
    save_vt_cache()

def vt_map_reputation(stats: dict) -> str:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    return "clean"

# NEW: in-process cache on top of file cache
@lru_cache(maxsize=2048)
def vt_enrich_ip(ip: str) -> Dict[str, Any]:
    if not ip:
        return {"status": "no_ip", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
    key = f"ip::{ip}"
    cached = cache_get(key)
    if cached:
        return cached
    if not VT_API_KEY:
        res = {"status": "disabled", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
        cache_set(key, res); return res
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    try:
        r = requests.get(url, headers=vt_headers(), timeout=10)
        if r.status_code == 200:
            data = r.json()
            stats = (data.get("data") or {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
            res = {
                "status": "ok",
                "reputation": vt_map_reputation(stats),
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "raw": data
            }
        elif r.status_code == 429:
            res = {"status": "rate_limited", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
        else:
            res = {"status": f"error_{r.status_code}", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
    except requests.Timeout:
        res = {"status": "error_timeout", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
    except Exception as e:
        res = {"status": f"error_{type(e).__name__}", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
    cache_set(key, res); return res

@lru_cache(maxsize=2048)
def vt_enrich_domain(domain: str) -> Dict[str, Any]:
    if not domain:
        return {"status": "no_domain", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
    key = f"domain::{domain.lower()}"
    cached = cache_get(key)
    if cached:
        return cached
    if not VT_API_KEY:
        res = {"status": "disabled", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
        cache_set(key, res); return res
    url = f"https://www.virustotal.com/api/v3/domains/{domain}"
    try:
        r = requests.get(url, headers=vt_headers(), timeout=10)
        if r.status_code == 200:
            data = r.json()
            stats = (data.get("data") or {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
            res = {
                "status": "ok",
                "reputation": vt_map_reputation(stats),
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "raw": data
            }
        elif r.status_code == 429:
            res = {"status": "rate_limited", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
        else:
            res = {"status": f"error_{r.status_code}", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
    except requests.Timeout:
        res = {"status": "error_timeout", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
    except Exception as e:
        res = {"status": f"error_{type(e).__name__}", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
    cache_set(key, res); return res

@lru_cache(maxsize=2048)
def vt_enrich_hash(hash_value: str) -> Dict[str, Any]:
    if not hash_value or not HASH_RE.match(hash_value.strip()):
        return {"status": "no_hash", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
    hv = hash_value.strip().lower()
    key = f"hash::{hv}"
    cached = cache_get(key)
    if cached:
        return cached
    if not VT_API_KEY:
        res = {"status": "disabled", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
        cache_set(key, res); return res
    url = f"https://www.virustotal.com/api/v3/files/{hv}"
    try:
        r = requests.get(url, headers=vt_headers(), timeout=10)
        if r.status_code == 200:
            data = r.json()
            stats = (data.get("data") or {}).get("attributes", {}).get("last_analysis_stats", {}) or {}
            res = {
                "status": "ok",
                "reputation": vt_map_reputation(stats),
                "malicious": int(stats.get("malicious", 0)),
                "suspicious": int(stats.get("suspicious", 0)),
                "harmless": int(stats.get("harmless", 0)),
                "raw": data
            }
        elif r.status_code == 404:
            res = {"status": "not_found", "reputation": "unknown", "malicious": 0, "suspicious": 0, "harmless": 0, "raw": {}}
        elif r.status_code == 429:
            res = {"status": "rate_limited", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
        else:
            res = {"status": f"error_{r.status_code}", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
    except requests.Timeout:
        res = {"status": "error_timeout", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
    except Exception as e:
        res = {"status": f"error_{type(e).__name__}", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "raw": {}}
    cache_set(key, res); return res

# NEW: friendlier captions for VT boxes
def vt_caption(data: Dict[str, Any], missing_label: str) -> str:
    status = data.get("status")
    if status in ["no_ip", "no_domain", "no_hash"]:
        return missing_label
    return f"mal:{data.get('malicious')} sus:{data.get('suspicious')} har:{data.get('harmless')} status:{status}"

# =========================
# Guardrails / approval / escalation
# =========================
def any_malicious(*reps: str) -> bool:
    return any(r == "malicious" for r in reps)

def guardrails_and_flags(actions: List[str], severity: str, confidence: int,
                         ip_rep: str, domain_rep: str, hash_rep: str) -> Tuple[List[str], bool]:
    """
    Returns (safe_actions, approval_needed).
    Forceful actions auto-allowed if:
      - severity HIGH/CRITICAL and confidence >= 85, OR
      - any reputation (ip/domain/hash) is 'malicious'.
    Otherwise, prefix with '(Approval)' and flag approval_needed.
    """
    safe: List[str] = []
    approval_needed = False
    can_force = (severity in ["high", "critical"] and confidence >= 85) or any_malicious(ip_rep, domain_rep, hash_rep)
    for a in actions:
        lower = a.lower()
        if any(x in lower for x in ["isolate", "block ip", "block domain", "quarantine", "disable account", "block hash"]):
            if can_force:
                safe.append(a)
            else:
                safe.append(f"(Approval) {a}")
                approval_needed = True
        else:
            safe.append(a)
    return safe, approval_needed

def auto_escalate(severity: str, confidence: int,
                  ip_rep: str, domain_rep: str, hash_rep: str) -> bool:
    """
    Return True when AI should *recommend* escalation to Tier 2.

    This does NOT move the alert into the Escalations bucket by itself;
    the alert only appears under Escalations when a human clicks
    "Escalate to Tier 2" (which sets status = "Escalated to Tier 2").
    """
    severity = (severity or "medium").lower()
    confidence = int(confidence or 0)

    # High/Critical with good confidence -> recommend escalation
    if severity in ("high", "critical") and confidence >= 80:
        return True

    # Any malicious reputation -> recommend escalation
    if any_malicious(ip_rep, domain_rep, hash_rep):
        return True

    return False


# NEW: decide initial workflow status from AI triage (for bulk "Run All")
def derive_status_from_triage(tri: Dict[str, Any]) -> str:
    """
    Decide initial workflow status from AI result.

    - If AI believes the alert is safe to close, we set
      tri["closure_recommended"] = True and return "Awaiting Approval"
      so a human can confirm the closure.
    - Everything else that is still open -> "Needs Review".
    - Nothing is auto-closed or auto-escalated into the Escalations tab.
    """

    sev = (tri.get("severity") or "medium").lower()
    conf = int(tri.get("confidence", 0) or 0)

    ip_rep = tri.get("ip_reputation", "unknown")
    dom_rep = tri.get("domain_reputation", "unknown")
    hash_rep = tri.get("hash_reputation", "unknown")

    # "Safe-ish" reputations
    safe_reps = all(r in ("clean", "unknown") for r in (ip_rep, dom_rep, hash_rep))

    # We only recommend closure if:
    # - AI is not recommending escalation
    # - No risky actions needing explicit approval
    # - Reputations aren’t malicious/suspicious
    # - Severity is LOW/MEDIUM
    # - Confidence reasonably high (>= 70)
    closure_recommended = (
        not tri.get("escalate") and
        not tri.get("approval_needed") and
        safe_reps and
        sev in ("low", "medium") and
        conf >= 70
    )

    tri["closure_recommended"] = closure_recommended

    if closure_recommended:
        # Put this into the "Awaiting Approval" bucket so a human
        # can approve the closure.
        return "Awaiting Approval"

    # Everything else is still something a Tier-1 analyst should review.
    return "Needs Review"


# =========================
# Strict JSON schema for AI (requires ip/domain/hash reputations)
# =========================
TRIAGE_JSON_SCHEMA = {
    "name": "triage_result",
    "strict": True,
    "schema": {
        "type": "object",
        "properties": {
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "category": {"type": "string"},
            "confidence": {"type": "integer", "minimum": 0, "maximum": 100},
            "ip_reputation": {"type": "string", "enum": ["malicious", "suspicious", "clean", "unknown"]},
            "domain_reputation": {"type": "string", "enum": ["malicious", "suspicious", "clean", "unknown"]},
            "hash_reputation": {"type": "string", "enum": ["malicious", "suspicious", "clean", "unknown"]},
            "summary": {"type": "string"},
            "actions": {"type": "array", "items": {"type": "string"}}
        },
        "required": [
            "severity",
            "category",
            "confidence",
            "ip_reputation",
            "domain_reputation",
            "hash_reputation",
            "summary",
            "actions"
        ],
        "additionalProperties": False
    }
}

# =========================
# AI triage
# =========================
def ai_triage(alert: Dict[str, Any], ip_rep: str, domain_rep: str, hash_rep: str) -> Dict[str, Any]:
    """
    Call OpenAI with schema-enforced JSON, feed all enrichment, then apply guardrails and escalation.
    """
    enrichment = {
        "ip_reputation": ip_rep,
        "domain_reputation": domain_rep,
        "hash_reputation": hash_rep
    }

    system_prompt = (
        "You are a Tier-1 SOC triage assistant. "
        "Given an alert and enrichment, classify severity and category, "
        "estimate confidence (0-100), and recommend concise, SAFE steps. "
        "Do NOT invent enrichment that wasn't provided."
    )

    user_prompt = (
        "ALERT JSON:\n" + json.dumps(alert, indent=2) +
        "\n\nENRICHMENT:\n" + json.dumps(enrichment, indent=2) +
        "\n\nTask: Produce a triage object that matches the JSON schema."
    )

    if client is None:
        tri = {
            "severity": "medium",
            "category": "unknown",
            "confidence": 50,
            "ip_reputation": ip_rep if ip_rep in ["malicious","suspicious","clean"] else "unknown",
            "domain_reputation": domain_rep if domain_rep in ["malicious","suspicious","clean"] else "unknown",
            "hash_reputation": hash_rep if hash_rep in ["malicious","suspicious","clean"] else "unknown",
            "summary": "AI disabled (no OPENAI_API_KEY). Using rule-based fallback.",
            "actions": ["Review alert manually", "Verify enrichment sources", "Gather EDR process tree"]
        }
    else:
        try:
            resp = client.chat.completions.create(
                model=MODEL_NAME,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                response_format={"type": "json_schema", "json_schema": TRIAGE_JSON_SCHEMA},
                temperature=0.2,
            )
            content = resp.choices[0].message.content if resp.choices else ""
            tri = json.loads(content) if content else {}
        except Exception as e:
            tri = {
                "severity": "medium",
                "category": "unknown",
                "confidence": 50,
                "ip_reputation": ip_rep if ip_rep in ["malicious","suspicious","clean"] else "unknown",
                "domain_reputation": domain_rep if domain_rep in ["malicious","suspicious","clean"] else "unknown",
                "hash_reputation": hash_rep if hash_rep in ["malicious","suspicious","clean"] else "unknown",
                "summary": f"Fallback triage due to error: {e}",
                "actions": ["Review alert manually", "Verify enrichment sources", "Gather EDR process tree"]
            }

    # Guardrails + approval + escalation
    sev = tri.get("severity", "medium")
    conf = tri.get("confidence", 50)
    tri["actions"], tri["approval_needed"] = guardrails_and_flags(
        tri.get("actions", []), sev, conf, ip_rep, domain_rep, hash_rep
    )
    tri["escalate"] = auto_escalate(sev, conf, ip_rep, domain_rep, hash_rep)

    # Ensure reputations present even if model omitted them
    tri.setdefault("ip_reputation", ip_rep)
    tri.setdefault("domain_reputation", domain_rep)
    tri.setdefault("hash_reputation", hash_rep)
    return tri

# =========================
# STREAMLIT UI (Interactive Analyst Console)
# =========================
st.set_page_config(page_title="SOC Agent Console", layout="wide")

# Column weights used for header/rows (keeps alignment consistent)
COLS_WEIGHTS = [0.9, 3.0, 1.1, 1.1, 1.1, 1.1]

# --- Topbar (centered title above intro card) ---
st.markdown("""
<style>
.topbar-center {
  display: flex;
  flex-direction: column;
  align-items: center;
  text-align: center;
  max-width: 900px;
  margin: 1.5rem auto 1rem auto;
  padding: 0 1rem;
}

/* Title styling */
.topbar-center .title {
  font-size: 2.6rem;
  font-weight: 850;
  line-height: 1.25;
  margin-bottom: 0.8rem;
  letter-spacing: .3px;
}

/* Description card */
.intro-card {
  background: rgba(245,246,248,0.9);
  border: 1px solid rgba(0,0,0,.06);
  border-radius: 16px;
  padding: 1rem 1.4rem 1.1rem 1.4rem;
  box-shadow: 0 2px 4px rgba(0,0,0,.06);
  backdrop-filter: blur(3px);
  max-width: 680px;
}
.intro-card .intro-title {
  font-weight: 700;
  font-size: 1.15rem;
  margin: 0 0 .5rem 0;
}
.intro-card .intro-text {
  margin: 0 0 .4rem 0;
  line-height: 1.45;
}
.intro-card ul {
  list-style-type: disc;
  padding-left: 1.4rem;
  margin: .5rem 0 .6rem 0;
  text-align: left;
  line-height: 1.55;
}
.intro-card li {
  margin: .2rem 0;
  font-size: .97rem;
}

/* Subtle bullet color for dark theme */
@media (prefers-color-scheme: dark){
  .intro-card {
    background: rgba(34,37,42,.45);
    border-color: rgba(255,255,255,.15);
    box-shadow: 0 2px 5px rgba(0,0,0,.4);
  }
  .intro-card ul { color: rgba(255,255,255,.9); }
  .intro-card li::marker { color: rgba(255,255,255,.55); }
}

/* Responsive adjustments */
@media (max-width: 900px){
  .topbar-center .title {
    font-size: 1.9rem;
    font-weight: 750;
  }
  .intro-card { padding: .9rem 1.1rem; }
}
</style>

<div class="topbar-center">
  <div class="title">Tier-1 SOC Agent — Interactive Console</div>
  <div class="intro-card">
    <div class="intro-title">AI-Powered SOC Analyst Assistant</div>
    <p class="intro-text">
      Welcome to the SOC Analyst AI Assistant — a demonstration of how artificial intelligence can augment Tier-1 Security Operations workflows. This dashboard:
    </p>
    <ul>
      <li>Simulates real-world SOC alerts</li>
      <li>Enriches indicators using VirusTotal</li>
      <li>Performs AI-driven triage via OpenAI</li>
      <li>Keeps a human analyst in control through approvals and escalation logic</li>
    </ul>
    <p class="intro-text" style="font-size:.92rem;opacity:.9;">
      Use the sidebar to manage options, load sample alerts, or upload a CSV.
    </p>
  </div>
</div>
""", unsafe_allow_html=True)

# Sidebar: environment + mode + bulk features
st.sidebar.header("Environment")
st.sidebar.write(f"**OpenAI API Key:** {'✅ Found' if OPENAI_API_KEY else '❌ Missing'}")
st.sidebar.write(f"**VirusTotal API Key:** {'✅ Found' if VT_API_KEY else '❌ Missing'}")

st.sidebar.header("Mode")
auto_triage = st.sidebar.toggle("Auto-Triage new alerts", value=False, help="If ON, AI triage runs automatically when alerts are added.")

st.sidebar.header("Bulk Actions")
if st.sidebar.button("Load Sample Pack (10 alerts)"):
    base = len(st.session_state.get("alerts", [])) + 1
    pack = []
    for i in range(base, base + 10):
        pack.append({
            "alert_id": str(i).zfill(3),
            "alert_name": "Inbound Port Scan" if i % 2 else "Multiple Failed Logins",
            "hostname": f"host-{i%5}",
            "ip": f"10.0.0.{(i%250)+1}",
            "domain": "" if i % 3 else "suspicious-example.biz",
            "hash": "" if i % 4 else "44d88612fea8a8f36de82e1278abb02f",
            "user": "SYSTEM" if i % 2 else "jdoe",
            "details": "Auto-generated sample"
        })
    st.session_state.setdefault("alerts", [])
    st.session_state["alerts"].extend(pack)

uploaded = st.sidebar.file_uploader(
    "Upload alerts CSV",
    type=["csv"],
    help="Columns supported: alert_id, alert_name, hostname, ip, domain, hash, user, details"
)

# Safe CSV handling (prevents weird uploads from breaking state) + size cap
required_cols = {"alert_id", "alert_name", "hostname", "ip", "domain", "hash", "user", "details"}
MAX_UPLOAD_BYTES = 4 * 1024 * 1024  # 4 MB
if uploaded:
    if getattr(uploaded, "size", 0) > MAX_UPLOAD_BYTES:
        st.sidebar.error("CSV too large (max 4 MB).")
    else:
        try:
            df_up = pd.read_csv(uploaded).fillna("")
            missing = required_cols - set(df_up.columns)
            if missing:
                st.sidebar.error(f"Uploaded CSV missing columns: {', '.join(sorted(missing))}")
            else:
                new_alerts = df_up.to_dict(orient="records")
                st.session_state.setdefault("alerts", [])
                st.session_state["alerts"].extend(new_alerts)
                st.sidebar.success(f"Loaded {len(new_alerts)} alerts from CSV")
        except Exception as e:
            st.sidebar.error(f"Failed to read CSV: {e}")

# Session state init
if "alerts" not in st.session_state:
    st.session_state.alerts = SAMPLE_ALERTS.copy()
if "results" not in st.session_state:
    st.session_state.results: Dict[str, Dict[str, Any]] = {}
if "workflow" not in st.session_state:
    # alert_id -> {status, owner, notes[], checklist{action: done}}
    st.session_state.workflow: Dict[str, Dict[str, Any]] = {}

# ---------- Top dashboard categorization helpers ----------
def _row(alert_id: str, tri: Dict[str, Any], wf: Dict[str, Any]) -> Dict[str, Any]:
    base_status = wf.get("status", "New")
    status_label = base_status

    # Add a visual tag for AI-recommended closures that are awaiting approval
    if tri.get("closure_recommended") and base_status == "Awaiting Approval":
        status_label = "Awaiting Approval (closure recommended)"

    return {
        "alert_id": alert_id,
        "name": next(
            (a["alert_name"] for a in st.session_state.alerts if a["alert_id"] == alert_id),
            ""
        ),
        "severity": tri.get("severity", "medium").upper(),
        "confidence": tri.get("confidence", 0),
        "status": status_label,
        "summary": (tri.get("summary") or "")[:140]
        + ("…" if len(tri.get("summary", "")) > 140 else ""),
    }

def build_sets():
    results = st.session_state.results
    wf_all = st.session_state.workflow

    escalations, awaiting, needs_human, closed = [], [], [], []

    for aid, tri in results.items():
        wf = wf_all.get(aid, {})
        row = _row(aid, tri, wf)

        status = (wf.get("status") or "New")

        # Escalations tab: ONLY things a human manually escalated
        if status == "Escalated to Tier 2":
            escalations.append(row)

        # Awaiting Approval tab: closure recommended, waiting for human decision
        elif status == "Awaiting Approval":
            awaiting.append(row)

        # Closed tab: explicitly closed by a human
        elif status == "Closed":
            closed.append(row)

        # Needs Review tab: everything else that is still open
        else:
            needs_human.append(row)

    return escalations, awaiting, needs_human, closed


# =========================
# Human Oversight Dashboard (TOP)
# =========================
st.markdown("""
<style>
/* Keep the tight layout but ensure the main title isn't clipped */
div.block-container h1:first-child { margin-top: .6rem !important; }

/* Section title + sub */
.hod-title { font-size: 1.6rem; font-weight: 700; margin: 0 0 .3rem 0; }
.hod-sub { color: rgba(0,0,0,.65); margin-bottom: .6rem; }

/* Cards row and styling */
.hod-cards { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: .75rem; margin-bottom: .6rem; }
.hod-card {
  border: 1px solid rgba(0,0,0,.06) !important;
  border-radius: 14px !important;
  padding: .9rem .9rem !important;
  background: rgba(245,246,248,0.9) !important;
  box-shadow: 0 1px 3px rgba(0,0,0,.05) !important;
  backdrop-filter: blur(3px) !important;
}
.hod-card:hover {
  background: rgba(237,239,242,1) !important;
  box-shadow: 0 2px 5px rgba(0,0,0,.08) !important;
}

/* Card labels & chips */
.hod-label { font-weight: 600; font-size: .95rem; display: flex; align-items: center; gap: .55rem; color: rgba(0,0,0,.88) !important; }  /* gap tweaked */
.hod-chip { display:inline-block; padding:.22rem .62rem; border-radius:999px; font-weight:700; font-size:.9rem; border:1px solid transparent; }  /* padding tweaked */
.hod-chip-esc  { background: rgba(239,68,68,.14) !important;  color: #7f1d1d !important; border-color: rgba(239,68,68,.38) !important; }
.hod-chip-apr  { background: rgba(245,158,11,.16) !important; color: #7c2d12 !important; border-color: rgba(245,158,11,.40) !important; }
.hod-chip-need { background: rgba(59,130,246,.14) !important;  color: #1e3a8a !important; border-color: rgba(59,130,246,.38) !important; }
.hod-chip-clo  { background: rgba(16,185,129,.14) !important;  color: #065f46 !important; border-color: rgba(16,185,129,.38) !important; }

.hod-note { color: rgba(0,0,0,.62) !important; }

/* Badges */
.hod-badge { display:inline-block; padding:.1rem .45rem; border-radius:10px; font-size:.80rem; font-weight:700; }
.badge-sev-CRITICAL { background:#ef4444; color:white; }
.badge-sev-HIGH     { background:#f97316; color:white; }
.badge-sev-MEDIUM   { background:#f59e0b; color:white; }
.badge-sev-LOW      { background:#10b981; color:white; }
.badge-sts { background:rgba(0,0,0,.08) !important; color:rgba(0,0,0,.85) !important; }

/* Make ALL text inside the tabbed lists readable by default */
.hod-list, .hod-list * { color: rgba(0,0,0,.90) !important; }
@media (prefers-color-scheme: dark) {
  .hod-list, .hod-list * { color: rgba(255,255,255,.92) !important; }
  .badge-sts { background: rgba(255,255,255,.16) !important; color: rgba(255,255,255,.92) !important; }
}

/* Left-side cells readability */
.hod-sum, .hod-sum * { color: rgba(0,0,0,.92) !important; }
@media (prefers-color-scheme: dark) {
  .hod-sum, .hod-sum * { color: rgba(255,255,255,.92) !important; }
}
</style>
""", unsafe_allow_html=True)

st.markdown('<div class="hod-title">Human Oversight Dashboard</div>', unsafe_allow_html=True)

esc, await_appr, needs, closed = build_sets()

# Cards row
c1, c2, c3, c4 = st.columns(4)
with c1:
    st.markdown(f"""
    <div class="hod-card">
      <div class="hod-label"> Escalations <span class="hod-chip hod-chip-esc">{len(esc)}</span></div>
      <div class="hod-note">High/critical or flagged cases.</div>
    </div>
    """, unsafe_allow_html=True)
with c2:
    st.markdown(f"""
    <div class="hod-card">
      <div class="hod-label"> Awaiting Approval <span class="hod-chip hod-chip-apr">{len(await_appr)}</span></div>
      <div class="hod-note">Actions pending analyst approval.</div>
    </div>
    """, unsafe_allow_html=True)
with c3:
    st.markdown(f"""
    <div class="hod-card">
      <div class="hod-label"> Needs Review <span class="hod-chip hod-chip-need">{len(needs)}</span></div>
      <div class="hod-note">Open tasks, approvals, or escalations.</div>
    </div>
    """, unsafe_allow_html=True)
with c4:
    st.markdown(f"""
    <div class="hod-card">
      <div class="hod-label"> Closed <span class="hod-chip hod-chip-clo">{len(closed)}</span></div>
      <div class="hod-note">Resolved alerts (for reference).</div>
    </div>
    """, unsafe_allow_html=True)

# ---------- Tabbed lists with compact rows + jump buttons ----------
tab1, tab2, tab3, tab4 = st.tabs([
    f"Escalations ({len(esc)})",
    f"Awaiting Approval ({len(await_appr)})",
    f"Needs Review ({len(needs)})",   # Consistent naming
    f"Closed ({len(closed)})"
])

def _sev_badge(sev: str) -> str:
    sev = (sev or "MEDIUM").upper()
    cls = "badge-sev-" + ("CRITICAL" if sev == "CRITICAL" else "HIGH" if sev == "HIGH" else "LOW" if sev == "LOW" else "MEDIUM")
    return f'<span class="hod-badge {cls}">{sev}</span>'

def _sts_badge(sts: str) -> str:
    return f'<span class="hod-badge badge-sts">{(sts or "New")}</span>'

def _list_block(rows: List[Dict[str, Any]], key_prefix: str):
    if not rows:
        st.info("Nothing here. ✅")
        return

    # Optional: sort rows by severity then confidence (CRITICAL > HIGH > MEDIUM > LOW)
    sev_rank = {"CRITICAL": 3, "HIGH": 2, "MEDIUM": 1, "LOW": 0}
    rows = sorted(
        rows,
        key=lambda r: (sev_rank.get((r.get("severity") or "MEDIUM").upper(), 1), r.get("confidence", 0)),
        reverse=True
    )

    # Start wrapper
    st.markdown('<div class="hod-list">', unsafe_allow_html=True)

    # Header (uses same Streamlit column widths)
    header_cols = st.columns(COLS_WEIGHTS, gap="small")
    header_cols[0].markdown("**ID**")
    header_cols[1].markdown("**Name**")
    header_cols[2].markdown("**Severity**")
    header_cols[3].markdown("**Confidence**")
    header_cols[4].markdown("**Status**")
    header_cols[5].markdown("**Action**")

    # Thin separator
    st.markdown(
        '<div style="height:8px;border-bottom:1px solid rgba(0,0,0,.08);margin:.2rem 0 .4rem 0;"></div>',
        unsafe_allow_html=True
    )

    # Rows (unique keys)
    for i, r in enumerate(rows):
        sev_html = _sev_badge(r.get("severity"))
        sts_html = _sts_badge(r.get("status"))

        with st.container(border=False):
            cols = st.columns(COLS_WEIGHTS, gap="small")
            cols[0].markdown(f"<div class='hod-sum'><b>{r['alert_id']}</b></div>", unsafe_allow_html=True)
            cols[1].markdown(f"<div class='hod-sum'>{r.get('name','')}</div>", unsafe_allow_html=True)
            cols[2].markdown(sev_html, unsafe_allow_html=True)
            cols[3].markdown(f"{r.get('confidence',0)}%", unsafe_allow_html=True)
            cols[4].markdown(sts_html, unsafe_allow_html=True)

            btn_key = f"{key_prefix}_{i}_{r['alert_id']}_open"
            if cols[5].button("Open", key=btn_key):
                st.session_state["jump_to"] = r["alert_id"]
                st.toast(f"Opening alert {r['alert_id']}…")
    # No manual rerun needed; the button click already triggers one

                try:
                    st.rerun()
                except Exception:
                    st.experimental_rerun()


    # Close wrapper
    st.markdown('</div>', unsafe_allow_html=True)

# ---- Render the tab contents ----
with tab1: _list_block(esc, "esc")
with tab2: _list_block(await_appr, "apr")
with tab3: _list_block(needs, "need")
with tab4: _list_block(closed, "clo")

# --- Incoming Alerts (header + right-aligned 'Run All' button) ---
h1, h2 = st.columns([1, 0.32])  # tweak 0.32 -> 0.25 for a tighter button
with h1:
    st.subheader("Incoming Alerts")
with h2:
    run_all = st.button(
        "🔎 Run AI Triage on All",
        use_container_width=True,
        help="Runs AI triage on every alert using current VT enrichment."
    )

# Alerts table
df = pd.DataFrame(st.session_state.alerts)
st.dataframe(df, use_container_width=True)

# Handle 'Run All' click
if run_all:
    with st.spinner("Running AI triage on all alerts..."):
        for alert in st.session_state.alerts:
            aid = alert["alert_id"]

            # --- VT enrichment ---
            vt_ip = vt_enrich_ip(alert.get("ip", ""))
            vt_domain = (
                vt_enrich_domain(alert.get("domain", ""))
                if alert.get("domain")
                else {"reputation": "unknown"}
            )
            vt_hash = (
                vt_enrich_hash(alert.get("hash", ""))
                if alert.get("hash")
                else {"reputation": "unknown"}
            )

            # --- Run AI triage ---
            tri = ai_triage(
                alert,
                vt_ip.get("reputation", "unknown"),
                vt_domain.get("reputation", "unknown"),
                vt_hash.get("reputation", "unknown"),
            )

            # Store AI result
            st.session_state.results[aid] = tri

            # Decide final status (never auto-close)
            # - "Needs Review"  -> normal human review
            # - "Awaiting Approval" -> closure recommended; human must approve
            status = derive_status_from_triage(tri)

            # Anything that isn't fully resolved by a human is owned by an analyst
            owner = "Analyst" if status in ("Needs Review", "Awaiting Approval") else "AI"

            # Initialize / update workflow entry
            wf = st.session_state.workflow.setdefault(
                aid,
                {"status": status, "owner": owner, "notes": [], "checklist": {}},
            )
            wf["status"] = status
            wf["owner"] = owner
            wf["checklist"] = {
                action: wf["checklist"].get(action, False)
                for action in tri.get("actions", [])
            }

        # DONE triaging all alerts
        st.success("All triage complete.")

    # Immediately refresh so counters & tables update and per-alert cards show results
    try:
        st.rerun()
    except Exception:
        st.experimental_rerun()


# Add a single alert
with st.expander("➕ Add New Alert"):
    with st.form("new_alert_form"):
        cols = st.columns(3)
        alert_id = cols[0].text_input("Alert ID", value=str(len(st.session_state.alerts)+1).zfill(3))
        alert_name = cols[1].text_input("Alert Name", value="Custom Alert")
        hostname = cols[2].text_input("Hostname", value="host-01")
        cols2 = st.columns(3)
        ip = cols2[0].text_input("IP", value="10.0.0.99")
        domain = cols2[1].text_input("Domain (optional)", value="")
        hv = cols2[2].text_input("File Hash (optional MD5/SHA1/SHA256)", value="")
        cols3 = st.columns(2)
        user = cols3[0].text_input("User", value="user01")
        details = cols3[1].text_input("Details", value="Describe the event...")
        submitted = st.form_submit_button("Add")
        if submitted:
            st.session_state.alerts.append({
                "alert_id": alert_id, "alert_name": alert_name, "hostname": hostname,
                "ip": ip, "domain": domain, "hash": hv, "user": user, "details": details
            })
            st.success(f"Added alert {alert_id}")
            if auto_triage:
                vt_ip = vt_enrich_ip(ip)
                vt_domain = vt_enrich_domain(domain) if domain else {"reputation":"unknown"}
                vt_hash = vt_enrich_hash(hv) if hv else {"reputation":"unknown"}
                tri = ai_triage(st.session_state.alerts[-1],
                                vt_ip.get("reputation","unknown"),
                                vt_domain.get("reputation","unknown"),
                                vt_hash.get("reputation","unknown"))
                st.session_state.results[alert_id] = tri
                st.session_state.workflow[alert_id] = {
                    "status": "Triaged", "owner": "AI", "notes": [],
                    "checklist": {a: False for a in tri.get("actions", [])}
                }
                st.toast(f"Auto-triaged alert {alert_id}")
                # Immediately refresh so counters and sets update
                try:
                    st.rerun()
                except Exception:
                    st.experimental_rerun()

# Per-alert cards: enrichment, AI triage, workflow
st.subheader("Triage & Analyst Workflow")

# Consume the jump target ONCE for this run.
scroll_target = st.session_state.pop("jump_to", None)

for alert in st.session_state.alerts:
    aid = alert["alert_id"]
    label = f"Alert {aid}: {alert['alert_name']}"

    # Force-expanding ONLY the one alert we jumped to
    if scroll_target == aid:
        expander = st.expander(label, expanded=True)
    else:
        # Let Streamlit remember user-opened/closed state
        expander = st.expander(label)

    with expander:
        st.json(alert, expanded=False)

        # ... your enrichment, VT, triage, workflow UI follows here ...

        # -------------------
        # Enrichment
        # -------------------
        with st.spinner("Enriching (VirusTotal)..."):
            vt_ip = vt_enrich_ip(alert.get("ip", ""))
            vt_domain = (
                vt_enrich_domain(alert.get("domain", ""))
                if alert.get("domain")
                else {
                    "status": "no_domain",
                    "reputation": "unknown",
                    "malicious": None,
                    "suspicious": None,
                    "harmless": None,
                }
            )
            vt_hash = (
                vt_enrich_hash(alert.get("hash", ""))
                if alert.get("hash")
                else {
                    "status": "no_hash",
                    "reputation": "unknown",
                    "malicious": None,
                    "suspicious": None,
                    "harmless": None,
                }
            )

        cols = st.columns(3)
        with cols[0]:
            st.markdown("**IP (VT):**")
            st.metric("Reputation", vt_ip.get("reputation", "unknown").upper())
            st.caption(vt_caption(vt_ip, "No IP"))

        with cols[1]:
            st.markdown("**Domain (VT):**")
            st.metric("Reputation", vt_domain.get("reputation", "unknown").upper())
            st.caption(vt_caption(vt_domain, "No Domain"))

        with cols[2]:
            st.markdown("**Hash (VT):**")
            st.metric("Reputation", vt_hash.get("reputation", "unknown").upper())
            st.caption(vt_caption(vt_hash, "No Hash"))

        # -------------------
        # Run / Clear AI
        # -------------------
        cA, cB = st.columns([1, 1])

        if cA.button(f"🔎 Run AI on {aid}", key=f"run_{aid}"):
            with st.spinner("Contacting model..."):
                tri = ai_triage(
                    alert,
                    vt_ip.get("reputation", "unknown"),
                    vt_domain.get("reputation", "unknown"),
                    vt_hash.get("reputation", "unknown"),
                )
                st.session_state.results[aid] = tri
                st.session_state.workflow.setdefault(
                    aid, {"status": "Triaged", "owner": "AI", "notes": [], "checklist": {}}
                )
                st.session_state.workflow[aid]["status"] = "Triaged"
                st.session_state.workflow[aid]["owner"] = "AI"
                st.session_state.workflow[aid]["checklist"] = {
                    a: st.session_state.workflow[aid]["checklist"].get(a, False)
                    for a in tri.get("actions", [])
                }
                st.success("AI triage complete.")
            # Optional refresh to keep counters in sync if needed:
            try:
                st.rerun()
            except Exception:
                st.experimental_rerun()

        if cB.button(f"🗑️ Clear AI result {aid}", key=f"clr_{aid}"):
            st.session_state.results.pop(aid, None)
            st.session_state.workflow.pop(aid, None)
            st.info("Cleared triage & workflow state for this alert.")
            try:
                st.rerun()
            except Exception:
                st.experimental_rerun()

        # -------------------
        # Show AI outputs + workflow controls
        # -------------------
        tri = st.session_state.results.get(aid)
        if tri:
            escalate_badge = "⚠️ ESCALATE" if tri.get("escalate") else "✅ No Escalation"
            st.markdown(
                f"**IP:** `{tri.get('ip_reputation','unknown')}` | "
                f"**Domain:** `{tri.get('domain_reputation','unknown')}` | "
                f"**Hash:** `{tri.get('hash_reputation','unknown')}` | "
                f"**Severity:** `{tri['severity'].upper()}` | "
                f"**Confidence:** `{tri['confidence']}%` | **{escalate_badge}**"
            )
            st.markdown(f"**Category:** `{tri['category']}`")
            st.write("**Summary:**", tri["summary"])

            # ---------- Checklist ----------
            st.write("**Actions (Analyst Checklist):**")
            for action, done in st.session_state.workflow[aid]["checklist"].items():
                new_done = st.checkbox(action, value=done, key=f"chk_{aid}_{action}")
                st.session_state.workflow[aid]["checklist"][action] = new_done

            # ---------- Status + flags (once, outside the loop) ----------
            status = st.session_state.workflow[aid].get("status", "New")
            needs_approval = tri.get("approval_needed", False)
            closure_recommended = tri.get("closure_recommended", False)

            extra_bits = []
            if needs_approval:
                extra_bits.append("Approval Needed")
            if closure_recommended:
                extra_bits.append("Closure Recommended")

            extra = ""
            if extra_bits:
                extra = " | **" + " | ".join(extra_bits) + "**"

            st.write(f"**Status:** {status}{extra}")

            # ---------- Action buttons ----------
            c1, c2, c3 = st.columns(3)

            if c1.button(f"Mark Needs Review ({aid})"):
                st.session_state.workflow[aid]["status"] = "Needs Review"
                st.session_state.workflow[aid]["owner"] = "Analyst"
                try:
                    st.rerun()
                except Exception:
                    st.experimental_rerun()

            # Manual escalation to Tier 2
            if c2.button(f"Escalate to Tier 2 ({aid})"):
                tri["escalate"] = True
                st.session_state.results[aid] = tri  # write back updated triage
                st.session_state.workflow.setdefault(
                    aid,
                    {
                        "status": "Escalated to Tier 2",
                        "owner": "Tier 2",
                        "notes": [],
                        "checklist": {},
                    },
                )
                st.session_state.workflow[aid]["status"] = "Escalated to Tier 2"
                st.session_state.workflow[aid]["owner"] = "Tier 2"
                st.success("Alert escalated to Tier 2.")
                try:
                    st.rerun()
                except Exception:
                    st.experimental_rerun()

            if c3.button(f"Close Alert ({aid})"):
                st.session_state.workflow[aid]["status"] = "Closed"
                st.session_state.workflow[aid]["owner"] = "Analyst"
                st.success("Alert closed.")
                try:
                    st.rerun()
                except Exception:
                    st.experimental_rerun()

            # ---------- Analyst notes ----------
            st.write("**Analyst Notes:**")
            note = st.text_input(f"Add note for {aid}", key=f"note_{aid}")
            if st.button(f"Add Note ({aid})"):
                if note.strip():
                    st.session_state.workflow[aid]["notes"].append(
                        {"ts": int(time.time()), "text": note.strip()}
                    )
                    st.success("Note added.")
                    try:
                        st.rerun()
                    except Exception:
                        st.experimental_rerun()

            for n in st.session_state.workflow[aid]["notes"]:
                st.caption(f"- {n['ts']}: {n['text']}")

