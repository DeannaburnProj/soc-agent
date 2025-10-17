# app.py — SOC Tier-1 agent with VirusTotal IP enrichment, AI triage, guardrails, and logging

import os
import json
import csv
import time
from typing import Dict, Any, List, Optional

import requests
from openai import OpenAI

# =========================
# CONFIG
# =========================
MODEL_NAME = "gpt-4o-mini"  # fast + affordable; change later if you like
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY")
VT_API_KEY = os.environ.get("VT_API_KEY")  # VirusTotal API key (free public API works)

if not OPENAI_API_KEY:
    raise RuntimeError("OPENAI_API_KEY is not set. In CMD:  set OPENAI_API_KEY=sk-your-key")

client = OpenAI(api_key=OPENAI_API_KEY)

# Ensure logs directory exists
os.makedirs("logs", exist_ok=True)
CSV_PATH = "logs/triage_log.csv"
JSONL_PATH = "logs/triage_log.jsonl"

# =========================
# Sample alerts (your queue)
# =========================
alerts: List[Dict[str, Any]] = [
    {
        "alert_id": "001",
        "alert_name": "Suspicious PowerShell Execution",
        "hostname": "finance-pc",
        "ip": "10.0.0.15",
        "user": "svc_backup",
        "details": "PowerShell ran with encoded command"
    },
    {
        "alert_id": "002",
        "alert_name": "Multiple Failed Logins",
        "hostname": "hr-laptop",
        "ip": "10.0.0.23",
        "user": "jdoe",
        "details": "5 failed RDP login attempts"
    },
    {
        "alert_id": "003",
        "alert_name": "Unusual Outbound Traffic",
        "hostname": "server-01",
        "ip": "192.168.1.50",
        "user": "SYSTEM",
        "details": "Outbound connection to rare external IP"
    }
]

# =========================
# VirusTotal enrichment
# =========================
def enrich_ip_with_virustotal(ip: str) -> Dict[str, Any]:
    """
    Query VirusTotal v3 IP report and derive a simple reputation label.
    Free/public API limits: ~4 req/min, ~500/day. We'll handle 429 gracefully.
    Returns:
      {
        "status": "ok" | "disabled" | "error_xxx" | "error_rate_limited",
        "malicious": int | None,
        "suspicious": int | None,
        "harmless": int | None,
        "reputation": "malicious" | "suspicious" | "clean" | "unknown",
        "raw": {...}
      }
    """
    if not VT_API_KEY or not ip:
        return {"status": "disabled", "malicious": None, "suspicious": None, "harmless": None, "reputation": "unknown", "raw": {}}

    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"Accept": "application/json", "x-apikey": VT_API_KEY}

    try:
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            attr = data.get("data", {}).get("attributes", {})
            stats = attr.get("last_analysis_stats", {}) or {}
            malicious = int(stats.get("malicious", 0))
            suspicious = int(stats.get("suspicious", 0))
            harmless = int(stats.get("harmless", 0))

            # Simple mapping: any malicious -> "malicious"; else suspicious -> "suspicious"; else "clean"
            if malicious > 0:
                rep = "malicious"
            elif suspicious > 0:
                rep = "suspicious"
            else:
                rep = "clean"

            return {
                "status": "ok",
                "malicious": malicious,
                "suspicious": suspicious,
                "harmless": harmless,
                "reputation": rep,
                "raw": data
            }

        elif resp.status_code == 429:
            return {"status": "error_rate_limited", "malicious": None, "suspicious": None, "harmless": None, "reputation": "unknown", "raw": {}}
        else:
            return {"status": f"error_{resp.status_code}", "malicious": None, "suspicious": None, "harmless": None, "reputation": "unknown", "raw": {}}

    except requests.Timeout:
        return {"status": "error_timeout", "malicious": None, "suspicious": None, "harmless": None, "reputation": "unknown", "raw": {}}
    except Exception as e:
        return {"status": f"error_{type(e).__name__}", "malicious": None, "suspicious": None, "harmless": None, "reputation": "unknown", "raw": {}}

# =========================
# Guardrails, escalation, logging
# =========================
def guardrails(actions: List[str], severity: str, confidence: int, ip_rep: str) -> List[str]:
    """
    Safe recommendations:
    - Allow 'isolate/block/quarantine/disable account' ONLY if severity HIGH/CRITICAL AND confidence>=85, OR ip_rep='malicious'.
    - Otherwise, prepend '(Approval)'.
    """
    safe: List[str] = []
    can_force = (severity in ["high", "critical"] and confidence >= 85) or (ip_rep == "malicious")
    for a in actions:
        lower = a.lower()
        if any(x in lower for x in ["isolate", "block ip", "block domain", "quarantine", "disable account", "block hash"]):
            safe.append(a if can_force else f"(Approval) {a}")
        else:
            safe.append(a)
    return safe

def auto_escalate(severity: str, confidence: int, ip_rep: str) -> bool:
    """Escalate if severity is HIGH/CRITICAL, or malicious IP with confidence ≥75."""
    if severity in ["high", "critical"]:
        return True
    if ip_rep == "malicious" and confidence >= 75:
        return True
    return False

def append_logs(alert: Dict[str, Any], triage: Dict[str, Any]) -> None:
    """Write both JSONL and CSV entries for auditing."""
    os.makedirs("logs", exist_ok=True)

    # JSONL
    with open(JSONL_PATH, "a", encoding="utf-8") as jf:
        jf.write(json.dumps({"ts": int(time.time()), "alert": alert, "triage": triage}) + "\n")

    # CSV
    write_header = not os.path.exists(CSV_PATH)
    with open(CSV_PATH, "a", newline="", encoding="utf-8") as cf:
        writer = csv.DictWriter(
            cf,
            fieldnames=["ts", "alert_id", "alert_name", "hostname", "ip", "severity", "confidence", "category", "ip_reputation", "escalate", "summary"],
        )
        if write_header:
            writer.writeheader()
        writer.writerow({
            "ts": int(time.time()),
            "alert_id": alert.get("alert_id"),
            "alert_name": alert.get("alert_name"),
            "hostname": alert.get("hostname"),
            "ip": alert.get("ip"),
            "severity": triage.get("severity"),
            "confidence": triage.get("confidence"),
            "category": triage.get("category"),
            "ip_reputation": triage.get("ip_reputation"),
            "escalate": triage.get("escalate"),
            "summary": triage.get("summary"),
        })

# =========================
# JSON schema for structured output
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
            "summary": {"type": "string"},
            "actions": {"type": "array", "items": {"type": "string"}}
        },
        "required": ["severity", "category", "confidence", "ip_reputation", "summary", "actions"],
        "additionalProperties": False
    }
}

# =========================
# AI triage
# =========================
def ai_triage(alert: Dict[str, Any], ip_rep: str) -> Dict[str, Any]:
    """
    Calls OpenAI Chat Completions with JSON schema response_format.
    Applies guardrails & escalation policy. Returns structured dict.
    """
    system_prompt = (
        "You are a Tier-1 SOC triage assistant. "
        "Given an alert and enrichment, classify severity and category, "
        "estimate confidence (0-100), and recommend concise, SAFE steps. "
        "Do NOT invent enrichment that wasn't provided."
    )
    user_prompt = (
        "ALERT JSON:\n"
        + json.dumps(alert, indent=2)
        + "\n\nENRICHMENT:\n"
        + json.dumps({"ip_reputation": ip_rep}, indent=2)
        + "\n\nTask: Produce a triage object that matches the JSON schema."
    )

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
            "ip_reputation": ip_rep if ip_rep in ["malicious", "suspicious", "clean"] else "unknown",
            "summary": f"Fallback triage due to error: {e}",
            "actions": ["Review alert manually", "Verify enrichment sources", "Gather EDR process tree"],
        }

    # Guardrails + escalation
    tri["actions"] = guardrails(tri.get("actions", []), tri.get("severity", "medium"), tri.get("confidence", 50), ip_rep)
    tri["escalate"] = auto_escalate(tri.get("severity", "medium"), tri.get("confidence", 50), ip_rep)
    return tri

# =========================
# Main processing loop
# =========================
if __name__ == "__main__":
    for alert in alerts:
        print("\n=== New Alert Received ===")
        print(json.dumps(alert, indent=4))

        ip = alert.get("ip", "")

        # Real VirusTotal enrichment (or graceful fallback)
        vt = enrich_ip_with_virustotal(ip)
        ip_rep = vt.get("reputation", "unknown")

        # Visible enrichment summary
        if vt["status"] == "ok":
            print(f"\n[Enrichment: VirusTotal] malicious={vt['malicious']} suspicious={vt['suspicious']} harmless={vt['harmless']} -> reputation={ip_rep}")
        elif vt["status"] == "error_rate_limited":
            print("\n[Enrichment: VirusTotal] Rate limited (429). Using 'unknown' reputation.")
        elif vt["status"] == "disabled":
            print("\n[Enrichment: VirusTotal] Disabled (no VT_API_KEY). Using 'unknown' reputation.")
        else:
            print(f"\n[Enrichment: VirusTotal] Error ({vt['status']}). Using 'unknown' reputation.")

        triage = ai_triage(alert, ip_rep)

        print("\n=== AI Triage Summary ===")
        print(f"Alert ID: {alert['alert_id']}")
        print(f"IP Reputation: {triage['ip_reputation']}")
        print(f"Severity: {triage['severity'].upper()} (confidence {triage['confidence']}%)")
        print(f"Category: {triage['category']}")
        print(f"Escalate: {triage['escalate']}")
        print(f"Summary: {triage['summary']}")
        print("Actions:")
        for a in triage.get("actions", []):
            print(f" - {a}")

        append_logs(alert, triage)

    print("\n=== All Alerts Processed ===")
    print(f"Total alerts analyzed: {len(alerts)}")
    print(f"Logs: {CSV_PATH}  and  {JSONL_PATH}")


