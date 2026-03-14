"""
Attack Chain Correlation Engine
Links isolated anomaly alerts into full attack timelines.
"""

from typing import List, Dict
from collections import defaultdict
from loguru import logger


# Temporal window (seconds) to group related events into a chain
CHAIN_WINDOW_SECONDS = 3600  # 1 hour

# Attack stage ordering heuristic
STAGE_ORDER = {
    "network_scanning":    1,
    "credential_misuse":   2,
    "lateral_movement":    3,
    "api_abuse":           4,
    "data_exfiltration":   5,
    "behavioural_deviation": 6,
}


class AttackChainBuilder:
    """
    Correlates multiple anomaly alerts belonging to the same
    entity or session into ordered attack chain timelines.

    Example chain:
        Suspicious email → Credential login anomaly
            → Privilege escalation → Data access surge
    """

    def _parse_ts(self, ts: str) -> float:
        """Parse ISO timestamp to epoch float. Returns 0 on failure."""
        try:
            from datetime import datetime
            return datetime.fromisoformat(ts).timestamp()
        except Exception:
            return 0.0

    def build_chains(self, anomalies: List) -> List[Dict]:
        """Group anomalies by entity and build temporal chains."""
        # Group alerts by entity
        by_entity = defaultdict(list)
        for alert in anomalies:
            by_entity[alert.entity].append(alert)

        chains = []
        for entity, alerts in by_entity.items():
            if len(alerts) < 2:
                continue  # Single alert = not a chain

            # Sort by timestamp
            sorted_alerts = sorted(alerts, key=lambda a: self._parse_ts(a.timestamp))

            # Sliding window grouping
            chain_stages = []
            window_start = self._parse_ts(sorted_alerts[0].timestamp)

            for alert in sorted_alerts:
                ts = self._parse_ts(alert.timestamp)
                if ts - window_start <= CHAIN_WINDOW_SECONDS:
                    chain_stages.append(alert)
                else:
                    if len(chain_stages) >= 2:
                        chains.append(self._format_chain(entity, chain_stages))
                    chain_stages = [alert]
                    window_start = ts

            if len(chain_stages) >= 2:
                chains.append(self._format_chain(entity, chain_stages))

        logger.debug("Built {} attack chains from {} anomalies", len(chains), len(anomalies))
        return chains

    def _format_chain(self, entity: str, stages: List) -> Dict:
        """Format a chain into a structured timeline dict."""
        sorted_stages = sorted(stages, key=lambda a: STAGE_ORDER.get(a.anomaly_type, 99))
        max_severity   = max(s.severity for s in sorted_stages)
        chain_label    = self._label_chain(sorted_stages)

        return {
            "entity": entity,
            "chain_label": chain_label,
            "stage_count": len(sorted_stages),
            "max_severity": round(max_severity, 3),
            "timeline": [
                {
                    "step":         i + 1,
                    "event_id":     s.event_id,
                    "anomaly_type": s.anomaly_type,
                    "severity":     s.severity,
                    "timestamp":    s.timestamp,
                }
                for i, s in enumerate(sorted_stages)
            ],
        }

    def _label_chain(self, stages: List) -> str:
        """Generate a human-readable label for the chain."""
        types = [s.anomaly_type for s in stages]
        if "credential_misuse" in types and "lateral_movement" in types:
            return "Credential Compromise → Lateral Movement"
        if "network_scanning" in types and "credential_misuse" in types:
            return "Reconnaissance → Credential Attack"
        if "lateral_movement" in types and "data_exfiltration" in types:
            return "Lateral Movement → Data Exfiltration"
        if "api_abuse" in types and "data_exfiltration" in types:
            return "API Abuse → Data Exfiltration"
        return "Multi-Stage Behavioural Attack"
