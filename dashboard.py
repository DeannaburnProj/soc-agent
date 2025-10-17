# dashboard.py — SOC Tier-1 Interactive Analyst Console
# Features: VT enrichment (IP/Domain/Hash), AI triage (strict schema), guardrails,
# approval workflow, auto-triage, sample packs, CSV upload, VT cache, human workload panel,
# escalation workflow with queue & badges, closed alerts panel.

import os
import json
import re
import time
from typing import Dict, Any, List, Tuple

import pandas as pd
import requests
import streamlit as st
from openai import OpenAI

# =========================
# PAGE CONFIG + LANDING
# =========================
st.set_page_config(page_title="SOC Analyst AI Assistant", page_icon="🧠", layout="wide")

st.title("AI-Powered SOC Analyst Assistant")
st.markdown("""
Welcome to the **SOC Analyst AI Assistant** — a demonstration of how artificial intelligence 
can augment Tier-1 Security Operations workflows.

This dashboard:
- Simulates real-world SOC alerts  
- Enriches indicators using **VirusTotal**  
- Performs AI-driven triage via **OpenAI**  
- Keeps a **human analyst in control** through approvals and escalation logic  

Use the sidebar to manage options, load sample alerts, or upload a CSV.
""")
st.divider()

# =========================
# CONFIG
# =========================
MODEL_NAME = "gpt-4o-mini"
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")
client = OpenAI(api_key=OPENAI_API_KEY) if OPENAI_API_KEY else None

def now_ts() -> int:
    return int(time.time())

def fmt_ts(ts: int) -> str:
    try:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
    except Exception:
        return str(ts)

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

def cache_get(key: str):
    return VT_CACHE.get(key)

def cache_set(key: str, value: dict):
    VT_CACHE[key] = value
    save_vt_cache()

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

def vt_map_reputation(stats: dict) -> str:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    if malicious > 0:
        return "malicious"
    if suspicious > 0:
        return "suspicious"
    return "clean"

def vt_enrich_ip(ip: str) -> Dict[str, Any]:
    if not ip:
        return {"status": "no_ip", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": "No IP provided", "raw": {}}
    key = f"ip::{ip}"
    cached = cache_get(key)
    if cached:
        return cached
    if not VT_API_KEY:
        res = {"status": "disabled", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": "VirusTotal key missing", "raw": {}}
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
                "message": "Enrichment successful",
                "raw": data
            }
        elif r.status_code == 429:
            res = {"status": "rate_limited", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": "Rate limit reached — please retry in ~1 minute.", "raw": {}}
        else:
            res = {"status": f"error_{r.status_code}", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": f"VirusTotal API error ({r.status_code})", "raw": {}}
    except requests.Timeout:
        res = {"status": "error_timeout", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": "Network timeout — please retry.", "raw": {}}
    except Exception:
        res = {"status": "error", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": "Unexpected error — please retry.", "raw": {}}
    cache_set(key, res); return res

def vt_enrich_domain(domain: str) -> Dict[str, Any]:
    if not domain:
        return {"status": "no_domain", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": "No domain provided", "raw": {}}
    key = f"domain::{domain.lower()}"
    cached = cache_get(key)
    if cached:
        return cached
    if not VT_API_KEY:
        res = {"status": "disabled", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": "VirusTotal key missing", "raw": {}}
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
                "message": "Enrichment successful",
                "raw": data
            }
        elif r.status_code == 429:
            res = {"status": "rate_limited", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": "Rate limit reached — please retry in ~1 minute.", "raw": {}}
        else:
            res = {"status": f"error_{r.status_code}", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": f"VirusTotal API error ({r.status_code})", "raw": {}}
    except requests.Timeout:
        res = {"status": "error_timeout", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": "Network timeout — please retry.", "raw": {}}
    except Exception:
        res = {"status": "error", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": "Unexpected error — please retry.", "raw": {}}
    cache_set(key, res); return res

def vt_enrich_hash(hash_value: str) -> Dict[str, Any]:
    if not hash_value or not HASH_RE.match(hash_value.strip()):
        return {"status": "no_hash", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": "No valid hash provided", "raw": {}}
    hv = hash_value.strip().lower()
    key = f"hash::{hv}"
    cached = cache_get(key)
    if cached:
        return cached
    if not VT_API_KEY:
        res = {"status": "disabled", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": "VirusTotal key missing", "raw": {}}
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
                "message": "Enrichment successful",
                "raw": data
            }
        elif r.status_code == 404:
            res = {"status": "not_found", "reputation": "unknown", "malicious": 0, "suspicious": 0, "harmless": 0, "message": "Hash not found on VirusTotal", "raw": {}}
        elif r.status_code == 429:
            res = {"status": "rate_limited", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": "Rate limit reached — please retry in ~1 minute.", "raw": {}}
        else:
            res = {"status": f"error_{r.status_code}", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": f"VirusTotal API error ({r.status_code})", "raw": {}}
    except requests.Timeout:
        res = {"status": "error_timeout", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": "Network timeout — please retry.", "raw": {}}
    except Exception:
        res = {"status": "error", "reputation": "unknown", "malicious": None, "suspicious": None, "harmless": None, "message": "Unexpected error — please retry.", "raw": {}}
    cache_set(key, res); return res

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

def auto_escalate(severity: str, confidence: int, ip_rep: str, domain_rep: str, hash_rep: str) -> bool:
    if severity in ["high", "critical"]:
        return True
    if any_malicious(ip_rep, domain_rep, hash_rep) and confidence >= 75:
        return True
    return False

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
# Status badge helper
# =========================
def status_badge(status: str, escalated: bool) -> str:
    s = (status or "New").lower()
    if s == "closed":
        return "Status: :green[**CLOSED**]"
    if escalated or s == "escalated":
        return "Status: :red[**ESCALATED**]"
    if s == "awaiting approval":
        return "Status: :orange[**AWAITING APPROVAL**]"
    if s == "triaged":
        return "Status: :blue[**TRIAGED**]"
    return "Status: :gray[**NEW**]"

# =========================
# STREAMLIT UI (Interactive Analyst Console)
# =========================
st.title("Tier-1 SOC Agent — Interactive Console")

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
if uploaded:
    df_up = pd.read_csv(uploaded)
    df_up.fillna("", inplace=True)
    new_alerts = df_up.to_dict(orient="records")
    st.session_state.setdefault("alerts", [])
    st.session_state["alerts"].extend(new_alerts)
    st.sidebar.success(f"Loaded {len(new_alerts)} alerts from CSV")

# Session state init
if "alerts" not in st.session_state:
    st.session_state.alerts = SAMPLE_ALERTS.copy()
if "results" not in st.session_state:
    st.session_state.results: Dict[str, Dict[str, Any]] = {}
if "workflow" not in st.session_state:
    # alert_id -> {status, owner, notes[], checklist{action: done}, escalated, escalation_*}
    st.session_state.workflow: Dict[str, Dict[str, Any]] = {}

# Human workload overview
def workload_summary():
    total = len(st.session_state.alerts)
    triaged = sum(1 for aid in st.session_state.workflow if st.session_state.workflow[aid].get("status") in ["Triaged","Awaiting Approval","Escalated","Closed"])
    awaiting = sum(1 for aid in st.session_state.workflow if st.session_state.workflow[aid].get("status") == "Awaiting Approval")
    escalated = sum(1 for aid in st.session_state.workflow if st.session_state.workflow[aid].get("status") == "Escalated")
    closed = sum(1 for aid in st.session_state.workflow if st.session_state.workflow[aid].get("status") == "Closed")
    return total, triaged, awaiting, escalated, closed

st.subheader("Human Workload Overview")
t_total, t_triaged, t_await, t_escal, t_closed = workload_summary()
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Total Alerts", t_total)
c2.metric("AI Triaged", t_triaged)
c3.metric("Awaiting Approval", t_await)
c4.metric("Escalated", t_escal)
c5.metric("Closed", t_closed)

# Alerts table
st.subheader("Incoming Alerts")
df = pd.DataFrame(st.session_state.alerts)
st.dataframe(df, use_container_width=True)

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
                vt_domain = vt_enrich_domain(domain) if domain else {"reputation":"unknown", "status":"no_domain", "message": ""}
                vt_hash = vt_enrich_hash(hv) if hv else {"reputation":"unknown", "status":"no_hash", "message": ""}
                tri = ai_triage(st.session_state.alerts[-1],
                                vt_ip.get("reputation","unknown"),
                                vt_domain.get("reputation","unknown"),
                                vt_hash.get("reputation","unknown"))
                st.session_state.results[alert_id] = tri
                st.session_state.workflow[alert_id] = {
                    "status": "Triaged",
                    "owner": "AI",
                    "notes": [],
                    "checklist": {a: False for a in tri.get("actions", [])},
                    "escalated": tri.get("escalate", False),
                    "escalation_reason": "",
                    "escalation_ts": now_ts() if tri.get("escalate") else None,
                }
                st.toast(f"Auto-triaged alert {alert_id}")

# Per-alert cards: enrichment, AI triage, workflow
st.subheader("Triage & Analyst Workflow")
for alert in st.session_state.alerts:
    aid = alert["alert_id"]
    with st.expander(f"Alert {aid}: {alert['alert_name']}"):
        st.json(alert, expanded=False)

        # Enrichment
        with st.spinner("Enriching (VirusTotal)..."):
            vt_ip = vt_enrich_ip(alert.get("ip",""))
            vt_domain = vt_enrich_domain(alert.get("domain","")) if alert.get("domain") else {"status":"no_domain","reputation":"unknown","malicious":None,"suspicious":None,"harmless":None,"message":""}
            vt_hash = vt_enrich_hash(alert.get("hash","")) if alert.get("hash") else {"status":"no_hash","reputation":"unknown","malicious":None,"suspicious":None,"harmless":None,"message":""}

        cols = st.columns(3)
        with cols[0]:
            st.markdown("**IP (VT):**")
            st.metric("Reputation", vt_ip.get("reputation","unknown").upper())
            st.caption(
                f"mal:{vt_ip.get('malicious')} sus:{vt_ip.get('suspicious')} har:{vt_ip.get('harmless')} "
                f"status:{vt_ip.get('status')} | VT: {vt_ip.get('message','')}"
            )
        with cols[1]:
            st.markdown("**Domain (VT):**")
            st.metric("Reputation", vt_domain.get("reputation","unknown").upper())
            st.caption(
                f"mal:{vt_domain.get('malicious')} sus:{vt_domain.get('suspicious')} har:{vt_domain.get('harmless')} "
                f"status:{vt_domain.get('status')} | VT: {vt_domain.get('message','')}"
            )
        with cols[2]:
            st.markdown("**Hash (VT):**")
            st.metric("Reputation", vt_hash.get("reputation","unknown").upper())
            st.caption(
                f"mal:{vt_hash.get('malicious')} sus:{vt_hash.get('suspicious')} har:{vt_hash.get('harmless')} "
                f"status:{vt_hash.get('status')} | VT: {vt_hash.get('message','')}"
            )

        # Initialize workflow record if missing
        st.session_state.workflow.setdefault(aid, {
            "status": "New",
            "owner": "Analyst",
            "notes": [],
            "checklist": {},
            "escalated": False,
            "escalation_reason": "",
            "escalation_ts": None,
        })

        # Run / Clear AI
        cA, cB = st.columns([1,1])
        if cA.button(f"🔎 Run AI on {aid}", key=f"run_{aid}"):
            with st.spinner("Contacting model..."):
                tri = ai_triage(
                    alert,
                    vt_ip.get("reputation","unknown"),
                    vt_domain.get("reputation","unknown"),
                    vt_hash.get("reputation","unknown"),
                )
                st.session_state.results[aid] = tri
                wf = st.session_state.workflow[aid]
                wf["status"] = "Triaged"
                wf["owner"] = "AI"
                wf["checklist"] = {a: wf["checklist"].get(a, False) for a in tri.get("actions", [])}
                # auto-escalation hint from AI
                if tri.get("escalate") and not wf.get("escalated"):
                    wf["escalated"] = True
                    wf["status"] = "Escalated"
                    wf["escalation_reason"] = "AI suggested escalation"
                    wf["escalation_ts"] = now_ts()
                st.success("AI triage complete.")
        if cB.button(f"🗑️ Clear AI result {aid}", key=f"clr_{aid}"):
            st.session_state.results.pop(aid, None)
            st.session_state.workflow.pop(aid, None)
            st.info("Cleared triage & workflow state for this alert.")
            st.stop()

        # Show AI outputs + workflow controls
        tri = st.session_state.results.get(aid)
        wf = st.session_state.workflow.get(aid, {})

        # Status badges row
        st.markdown(f"**{status_badge(wf.get('status','New'), wf.get('escalated', False))}**")

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

            st.write("**Actions (Analyst Checklist):**")
            for action, done in wf.get("checklist", {}).items():
                new_done = st.checkbox(action, value=done, key=f"chk_{aid}_{action}")
                wf["checklist"][action] = new_done

            # Status & escalation controls
            needs_approval = tri.get("approval_needed", False)
            st.write(f"**Status:** {wf.get('status','New')} | **Approval Needed:** {'Yes' if needs_approval else 'No'}")

            c1, c2, c3, c4 = st.columns(4)
            if c1.button(f"Mark Awaiting Approval ({aid})"):
                wf["status"] = "Awaiting Approval"
                wf["owner"] = "Analyst"
            if c2.button(f"Approve Risky Actions ({aid})"):
                # remove "(Approval)" prefix
                clean_actions = [a.replace("(Approval) ", "") for a in tri.get("actions", [])]
                tri["actions"] = clean_actions
                tri["approval_needed"] = False
                wf["status"] = "Triaged"
                st.success("Approved. Actions updated.")
            if c3.button(f"Close Alert ({aid})"):
                wf["status"] = "Closed"
                wf["owner"] = "Analyst"
                st.success("Alert closed. It will also appear in the 'Closed Alerts' panel below.")
            # Escalation with reason
            esc_reason = c4.text_input(f"Escalation reason ({aid})", value=wf.get("escalation_reason",""), placeholder="Why escalate?")
            if st.button(f"🚨 Escalate to Tier-2 ({aid})"):
                wf["status"] = "Escalated"
                wf["escalated"] = True
                wf["owner"] = "Analyst"
                wf["escalation_reason"] = esc_reason.strip() if esc_reason else "No reason provided"
                wf["escalation_ts"] = now_ts()
                st.warning("Alert escalated. It will appear in the Escalation Queue.")

            # Notes
            st.write("**Analyst Notes:**")
            note = st.text_input(f"Add note for {aid}", key=f"note_{aid}")
            if st.button(f"Add Note ({aid})"):
                if note.strip():
                    wf.setdefault("notes", []).append({"ts": now_ts(), "text": note.strip()})
                    st.success("Note added.")
            for n in wf.get("notes", []):
                st.caption(f"- {fmt_ts(n['ts'])}: {n['text']}")

# Batch run on all
run_all = st.button("🔎 Run AI Triage on All (with current enrichment)")
if run_all:
    with st.spinner("Running AI triage on all alerts..."):
        for alert in st.session_state.alerts:
            vt_ip = vt_enrich_ip(alert.get("ip",""))
            vt_domain = vt_enrich_domain(alert.get("domain","")) if alert.get("domain") else {"reputation":"unknown", "status":"no_domain", "message": ""}
            vt_hash = vt_enrich_hash(alert.get("hash","")) if alert.get("hash") else {"reputation":"unknown", "status":"no_hash", "message": ""}
            tri = ai_triage(
                alert,
                vt_ip.get("reputation","unknown"),
                vt_domain.get("reputation","unknown"),
                vt_hash.get("reputation","unknown"),
            )
            aid = alert["alert_id"]
            st.session_state.results[aid] = tri
            st.session_state.workflow.setdefault(aid, {"status":"Triaged","owner":"AI","notes":[],"checklist":{}, "escalated": False, "escalation_reason": "", "escalation_ts": None})
            wf = st.session_state.workflow[aid]
            wf["status"] = "Triaged"
            wf["owner"] = "AI"
            wf["checklist"] = {a: wf["checklist"].get(a, False) for a in tri.get("actions", [])}
            if tri.get("escalate") and not wf.get("escalated"):
                wf["status"] = "Escalated"
                wf["escalated"] = True
                wf["escalation_reason"] = "AI suggested escalation"
                wf["escalation_ts"] = now_ts()
        st.success("All triage complete.")

# Escalation Queue panel
st.subheader("Escalation Queue")
esc_rows = []
for aid, wf in st.session_state.workflow.items():
    if wf.get("status") == "Escalated" or wf.get("escalated"):
        esc_rows.append({
            "alert_id": aid,
            "status": wf.get("status"),
            "reason": wf.get("escalation_reason",""),
            "when": fmt_ts(wf.get("escalation_ts")) if wf.get("escalation_ts") else "",
            "owner": wf.get("owner","Analyst"),
            "open_tasks": sum(1 for x in wf.get("checklist", {}).values() if not x)
        })
if esc_rows:
    st.dataframe(pd.DataFrame(esc_rows), use_container_width=True)
else:
    st.info("No active escalations.")

# Closed Alerts panel
st.subheader("Closed Alerts")
closed_rows = []
for aid, wf in st.session_state.workflow.items():
    if wf.get("status") == "Closed":
        closed_rows.append({
            "alert_id": aid,
            "closed_when": fmt_ts(wf.get("escalation_ts")) if wf.get("escalation_ts") else "",
            "owner": wf.get("owner","Analyst"),
            "notes": " / ".join(n.get("text","") for n in wf.get("notes", [])[:3])  # preview
        })
if closed_rows:
    st.dataframe(pd.DataFrame(closed_rows), use_container_width=True)
else:
    st.info("No closed alerts yet.")

# “What still needs a human?” panel (open actions or approvals)
st.subheader("What still needs a human?")
todo_rows = []
for aid, tri in st.session_state.results.items():
    wf = st.session_state.workflow.get(aid, {})
    if tri.get("approval_needed") or wf.get("status") in ["Awaiting Approval", "Escalated"]:
        todo_rows.append({
            "alert_id": aid,
            "status": wf.get("status", "New"),
            "approval_needed": tri.get("approval_needed", False),
            "escalate": wf.get("status") == "Escalated",
            "open_tasks": sum(1 for x in wf.get("checklist", {}).values() if not x)
        })
if todo_rows:
    st.dataframe(pd.DataFrame(todo_rows), use_container_width=True)
else:
    st.info("No items require human action right now ✅")




