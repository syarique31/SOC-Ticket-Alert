import json
import random
import time
from datetime import datetime, timezone

INCIDENT_TYPES = [
    "Credential Abuse",
    "Public App Exploitation",
    "Ransomware Execution",
    "Lateral Movement",
    "Data Exfiltration",
    "Reconnaissance Activity",
    "Malware Beaconing",
    "Privilege Escalation"
]

CATEGORY_ASSET_MAP = {
    "Credential Abuse": ("IAM", "Identity Platform"),
    "Public App Exploitation": ("AppSec", "Web Application"),
    "Ransomware Execution": ("Endpoint", "Workstations"),
    "Lateral Movement": ("Network", "Corporate Network"),
    "Data Exfiltration": ("Data", "Customer Data"),
    "Reconnaissance Activity": ("Network", "Public Infrastructure"),
    "Malware Beaconing": ("Endpoint", "Workstations"),
    "Privilege Escalation": ("IAM", "Directory Services")
}

TITLE_VARIANTS = {
    "Credential Abuse": [
        "Suspicious credential usage observed",
        "Abnormal authentication behavior detected"
    ],
    "Public App Exploitation": [
        "Exploit attempt against public web service",
        "Suspicious activity targeting web application"
    ],
    "Ransomware Execution": [
        "Ransomware-like behavior observed on endpoint",
        "Suspicious file encryption activity detected"
    ],
    "Lateral Movement": [
        "Suspicious lateral movement within network",
        "Unusual internal network activity observed"
    ],
    "Data Exfiltration": [
        "Unusual outbound data transfer detected",
        "Potential data exfiltration activity observed"
    ],
    "Reconnaissance Activity": [
        "Suspicious reconnaissance behavior observed",
        "Scanning activity detected from external source"
    ],
    "Malware Beaconing": [
        "Potential command-and-control communication observed",
        "Suspicious outbound beaconing behavior detected"
    ],
    "Privilege Escalation": [
        "Unauthorized privilege escalation attempt detected",
        "Suspicious elevation of privileges observed"
    ]
}

# -------------------------
# SEVERITY CALCULATION
# -------------------------
def calculate_severity(score):
    if score >= 11:
        return "Critical"
    elif score >= 8:
        return "High"
    elif score >= 5:
        return "Medium"
    else:
        return "Low"

# -------------------------
# INCIDENT GENERATION
# -------------------------
def generate_incident(i):
    incident = random.choice(INCIDENT_TYPES)
    category, asset = CATEGORY_ASSET_MAP[incident]

    exposure = random.choices(
        ["External", "Internal"],
        weights=[0.4, 0.6]
    )[0]

    # ↓↓↓ LOWER + REALISTIC BASELINES ↓↓↓
    likelihood = random.randint(1, 4)
    impact = random.randint(1, 4)
    exploitability = random.randint(0, 3)

    # External events slightly increase likelihood
    if exposure == "External":
        likelihood += random.choice([0, 1])

    # High-value assets slightly increase impact
    if category in ["Data", "IAM"]:
        impact += random.choice([0, 1])

    business_criticality = random.randint(2, 5)
    control_coverage = random.randint(1, 5)
    detection_gap = random.random() < (0.5 if control_coverage <= 2 else 0.2)
    confidence = round(random.uniform(0.65, 0.95), 2)

    score = likelihood + impact + exploitability
    severity = calculate_severity(score)

    return {
        "incident_id": f"INC-{i:05}",
        "title": random.choice(TITLE_VARIANTS[incident]),
        "incident_type": incident,
        "category": category,
        "asset": asset,
        "exposure": exposure,
        "severity": severity,
        "likelihood": likelihood,
        "impact": impact,
        "exploitability": exploitability,
        "business_criticality": business_criticality,
        "control_coverage": control_coverage,
        "detection_gap": detection_gap,
        "confidence": confidence,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }

# -------------------------
# MAIN LOOP
# -------------------------
LOG_FILE = "/tmp/security_alerts.log"

i = 1
while True:
    event = generate_incident(i)

    with open(LOG_FILE, "a") as f:
        f.write(json.dumps(event) + "\n")

    print(f"[+] Generated incident {event['incident_id']} ({event['severity']})")

    i += 1
    time.sleep(random.randint(5, 10))