"""
Dynamic Cyber Risk Scoring Module
Computes risk scores per user, device, and service entity.
"""

from dataclasses import dataclass
from typing import List, Dict
from loguru import logger


@dataclass
class RiskScore:
    entity: str
    entity_type: str       # user | device | service
    score: float           # 0–100
    risk_level: str        # LOW | MEDIUM | HIGH | CRITICAL
    contributing_factors: List[str]


# Scoring weights (tunable per organization profile)
WEIGHTS = {
    "anomaly_severity":         0.35,
    "alert_frequency":          0.20,
    "privilege_level":          0.15,
    "data_sensitivity":         0.20,
    "historical_incident_rate": 0.10,
}


def _risk_level(score: float) -> str:
    if score >= 80:
        return "CRITICAL"
    elif score >= 60:
        return "HIGH"
    elif score >= 35:
        return "MEDIUM"
    return "LOW"


class RiskScorer:
    """
    Computes dynamic risk scores for all entities observed in the event stream.
    
    Score formula:
        Risk = w1 * anomaly_severity
             + w2 * alert_frequency
             + w3 * privilege_level
             + w4 * data_sensitivity_accessed
             + w5 * historical_incident_rate
    """

    def score(self, events: List[Dict], anomalies: List) -> List[Dict]:
        """Compute risk scores grouped by entity."""
        entity_data: Dict[str, Dict] = {}

        # Aggregate raw metrics per entity
        for event in events:
            entity = event.get("user", event.get("device", "unknown"))
            if entity not in entity_data:
                entity_data[entity] = {
                    "entity_type": event.get("entity_type", "user"),
                    "privilege_level": event.get("privilege_level", 1),
                    "data_mb_accessed": 0,
                    "alert_count": 0,
                    "anomaly_severities": [],
                    "historical_incidents": event.get("historical_incidents", 0),
                }
            entity_data[entity]["data_mb_accessed"] += event.get("data_transferred_mb", 0)

        # Overlay anomaly signals
        for alert in anomalies:
            e = alert.entity
            if e in entity_data:
                entity_data[e]["alert_count"] += 1
                entity_data[e]["anomaly_severities"].append(alert.severity)

        # Compute final scores
        results = []
        for entity, data in entity_data.items():
            avg_severity   = sum(data["anomaly_severities"]) / max(len(data["anomaly_severities"]), 1)
            freq_norm      = min(data["alert_count"] / 10.0, 1.0)
            priv_norm      = min(data["privilege_level"] / 5.0, 1.0)
            data_norm      = min(data["data_mb_accessed"] / 1000.0, 1.0)
            hist_norm      = min(data["historical_incidents"] / 5.0, 1.0)

            raw_score = (
                WEIGHTS["anomaly_severity"]         * avg_severity
              + WEIGHTS["alert_frequency"]          * freq_norm
              + WEIGHTS["privilege_level"]          * priv_norm
              + WEIGHTS["data_sensitivity"]         * data_norm
              + WEIGHTS["historical_incident_rate"] * hist_norm
            )
            final_score = round(raw_score * 100, 1)

            factors = []
            if avg_severity > 0.6:   factors.append("high anomaly severity")
            if freq_norm > 0.5:      factors.append("frequent alerts")
            if priv_norm > 0.6:      factors.append("elevated privileges")
            if data_norm > 0.4:      factors.append("large data access volume")
            if hist_norm > 0.2:      factors.append("prior incident history")

            results.append({
                "entity":               entity,
                "entity_type":          data["entity_type"],
                "score":                final_score,
                "risk_level":           _risk_level(final_score),
                "contributing_factors": factors,
            })

        results.sort(key=lambda x: x["score"], reverse=True)
        logger.debug("Risk scores computed for {} entities", len(results))
        return results
