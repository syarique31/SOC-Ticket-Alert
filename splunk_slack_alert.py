import requests
import json
import time
import os
from requests.auth import HTTPBasicAuth

# =========================
# CONFIG (FROM ENV VARS)
# =========================
SPLUNK_HOST = os.getenv("SPLUNK_HOST")      # https://localhost:8089
SPLUNK_USER = os.getenv("SPLUNK_USER")      # admin
SPLUNK_PASS = os.getenv("SPLUNK_PASS")      # your Splunk password

SLACK_WEBHOOK_URL = "https://hooks.slack.com/services/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"

# MUST be one-line search for Splunk export API
SEARCH_QUERY = (
    'search index=security_alerts severity IN ("High","Critical") '
    '| sort - _time '
    '| head 3'
)

POLL_INTERVAL = 30  # seconds
sent_incidents = set()

# =========================
# VALIDATION
# =========================
print("========== CONFIG CHECK ==========")
print("[DEBUG] SPLUNK_HOST:", SPLUNK_HOST)
print("[DEBUG] SPLUNK_USER:", SPLUNK_USER)
print("[DEBUG] SPLUNK_PASS SET:", bool(SPLUNK_PASS))
print("[DEBUG] SLACK_WEBHOOK_URL SET:", bool(SLACK_WEBHOOK_URL))
print("==================================")

if not all([SPLUNK_HOST, SPLUNK_USER, SPLUNK_PASS]):
    raise EnvironmentError("❌ Missing SPLUNK_HOST, SPLUNK_USER, or SPLUNK_PASS")

# =========================
# FUNCTIONS
# =========================
def fetch_incidents():
    url = f"{SPLUNK_HOST}/services/search/jobs/export"
    data = {
        "search": SEARCH_QUERY,
        "output_mode": "json"
    }

    print("[DEBUG] Querying Splunk API...")
    response = requests.post(
        url,
        data=data,
        auth=HTTPBasicAuth(SPLUNK_USER, SPLUNK_PASS),
        verify=False,
        timeout=10
    )

    print("[DEBUG] Splunk status code:", response.status_code)

    if response.status_code != 200:
        print("[ERROR] Splunk response body:")
        print(response.text)
        raise Exception("Splunk API request failed")

    print("[DEBUG] Raw response (first 500 chars):")
    print(response.text[:500])

    incidents = []
    for line in response.text.splitlines():
        if line.strip():
            incidents.append(json.loads(line))

    print(f"[DEBUG] Parsed {len(incidents)} result rows")
    return incidents


def send_to_slack(event):
    print("[DEBUG] Sending event to Slack:", event.get("incident_id"))

    message = (
        "🚨 *SOC INCIDENT ALERT*\n"
        f"*ID:* {event.get('incident_id')}\n"
        f"*Severity:* {event.get('severity')}\n"
        f"*Type:* {event.get('incident_type')}\n"
        f"*Asset:* {event.get('asset')}\n"
        f"*Exposure:* {event.get('exposure')}\n"
        f"*Confidence:* {event.get('confidence')}\n"
        f"*Summary:* {event.get('title')}"
    )

    payload = {"text": message}
    resp = requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)

    print("[DEBUG] Slack response status:", resp.status_code)


# =========================
# MAIN LOOP
# =========================
print("\n[*] SOC Slack Alert Engine STARTED\n")

while True:
    try:
        results = fetch_incidents()

        for r in results:
            result = r.get("result", {})

            # 🔑 FIX: Parse JSON inside _raw
            raw = result.get("_raw")
            if not raw:
                continue

            event = json.loads(raw)
            incident_id = event.get("incident_id")

            print("[DEBUG] Processing incident:", incident_id)

            if incident_id and incident_id not in sent_incidents:
                send_to_slack(event)
                sent_incidents.add(incident_id)
                print(f"[+] ALERT SENT for {incident_id}")

        print(f"[DEBUG] Sleeping {POLL_INTERVAL}s...\n")
        time.sleep(POLL_INTERVAL)

    except Exception as e:
        print("❌ ERROR:", e)
        time.sleep(POLL_INTERVAL)