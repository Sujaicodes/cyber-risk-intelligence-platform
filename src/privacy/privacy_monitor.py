"""
Privacy Risk Monitoring Module
Detects unauthorized data access, bulk downloads, and exfiltration signals.
"""

from typing import List, Dict
from loguru import logger


# Thresholds (configurable)
BULK_DOWNLOAD_THRESHOLD_MB    = 200.0   # Flag downloads larger than this
OFF_HOURS_SENSITIVITY_FACTOR  = 1.5     # Multiply risk weight for off-hours events
HIGH_PRIVILEGE_QUERY_LIMIT    = 50      # Suspicious # of privileged resource queries


PRIVACY_RULES = [
    {
        "id":          "PRIV-001",
        "name":        "Bulk Sensitive Data Download",
        "check":       lambda e: e.get("data_transferred_mb", 0) > BULK_DOWNLOAD_THRESHOLD_MB,
        "severity":    "HIGH",
        "description": "Entity downloaded an unusually large volume of data.",
    },
    {
        "id":          "PRIV-002",
        "name":        "Off-Hours Sensitive Resource Access",
        "check":       lambda e: e.get("off_hours", False) and e.get("privilege_level", 1) >= 3,
        "severity":    "MEDIUM",
        "description": "Privileged resource access detected outside business hours.",
    },
    {
        "id":          "PRIV-003",
        "name":        "New Device Accessing Sensitive Data",
        "check":       lambda e: e.get("new_device", False) and e.get("data_transferred_mb", 0) > 50,
        "severity":    "HIGH",
        "description": "Sensitive data accessed from an unrecognized device.",
    },
    {
        "id":          "PRIV-004",
        "name":        "High-Volume API Data Extraction",
        "check":       lambda e: e.get("api_calls_per_min", 0) > 80 and e.get("data_transferred_mb", 0) > 100,
        "severity":    "CRITICAL",
        "description": "Combination of high API call rate and large data transfer suggests automated extraction.",
    },
    {
        "id":          "PRIV-005",
        "name":        "Lateral Movement + Data Access",
        "check":       lambda e: e.get("lateral_hops", 0) >= 2 and e.get("data_transferred_mb", 0) > 20,
        "severity":    "CRITICAL",
        "description": "Lateral movement followed by data access — potential insider threat or APT activity.",
    },
]


class PrivacyMonitor:
    """
    Evaluates events against privacy risk rules to detect
    unauthorized or suspicious access to sensitive data.
    """

    def analyze(self, events: List[Dict]) -> List[Dict]:
        """Run all privacy rules against the event stream."""
        alerts = []

        for event in events:
            for rule in PRIVACY_RULES:
                try:
                    if rule["check"](event):
                        alerts.append({
                            "rule_id":     rule["id"],
                            "rule_name":   rule["name"],
                            "severity":    rule["severity"],
                            "description": rule["description"],
                            "entity":      event.get("user", event.get("device", "unknown")),
                            "timestamp":   event.get("timestamp", ""),
                            "event_id":    event.get("id", ""),
                            "data_mb":     event.get("data_transferred_mb", 0),
                        })
                except Exception:
                    continue

        logger.debug("Privacy monitor flagged {} events", len(alerts))
        return alerts
