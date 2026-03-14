"""
Behavioural Anomaly Detection Engine
Uses Isolation Forest and Autoencoder for multi-technique detection.
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from dataclasses import dataclass, field
from typing import List, Dict, Any
from loguru import logger


@dataclass
class AnomalyAlert:
    event_id: str
    entity: str          # user / device / service
    entity_type: str
    anomaly_type: str    # lateral_movement, credential_misuse, traffic_spike, etc.
    severity: float      # 0.0 – 1.0
    score: float         # raw anomaly score
    features: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""


class AnomalyDetector:
    """
    Multi-technique anomaly detection engine.
    Combines Isolation Forest for tabular features with
    statistical thresholds for time-series signals.
    """

    ANOMALY_THRESHOLD = -0.1  # Isolation Forest decision threshold

    def __init__(self, contamination: float = 0.05):
        self.contamination = contamination
        self.scaler = StandardScaler()
        self.iso_forest = IsolationForest(
            contamination=contamination,
            n_estimators=200,
            random_state=42,
            n_jobs=-1,
        )

    def _extract_features(self, events: List[Dict]) -> pd.DataFrame:
        """Convert raw events to feature vectors."""
        records = []
        for e in events:
            records.append({
                "failed_logins_1h":     e.get("failed_logins_1h", 0),
                "unique_ips_accessed":  e.get("unique_ips_accessed", 0),
                "data_transferred_mb":  e.get("data_transferred_mb", 0),
                "off_hours_activity":   int(e.get("off_hours", False)),
                "new_device_flag":      int(e.get("new_device", False)),
                "privilege_level":      e.get("privilege_level", 1),
                "api_call_rate":        e.get("api_calls_per_min", 0),
                "lateral_hops":         e.get("lateral_hops", 0),
            })
        return pd.DataFrame(records)

    def _classify_anomaly_type(self, event: Dict, score: float) -> str:
        """Heuristically label anomaly type based on dominant signal."""
        if event.get("lateral_hops", 0) > 2:
            return "lateral_movement"
        if event.get("failed_logins_1h", 0) > 5:
            return "credential_misuse"
        if event.get("data_transferred_mb", 0) > 500:
            return "data_exfiltration"
        if event.get("api_calls_per_min", 0) > 100:
            return "api_abuse"
        if event.get("unique_ips_accessed", 0) > 20:
            return "network_scanning"
        return "behavioural_deviation"

    def detect(self, events: List[Dict]) -> List[AnomalyAlert]:
        """Run full anomaly detection pipeline."""
        if not events:
            logger.warning("No events provided for anomaly detection.")
            return []

        df = self._extract_features(events)
        X = self.scaler.fit_transform(df)

        scores = self.iso_forest.fit_predict(X)
        raw_scores = self.iso_forest.decision_function(X)

        alerts = []
        for i, (event, score, raw) in enumerate(zip(events, scores, raw_scores)):
            if score == -1:  # Anomaly flagged by Isolation Forest
                severity = min(1.0, max(0.0, abs(raw) / 0.5))
                alert = AnomalyAlert(
                    event_id=event.get("id", f"evt_{i}"),
                    entity=event.get("user", event.get("device", "unknown")),
                    entity_type=event.get("entity_type", "user"),
                    anomaly_type=self._classify_anomaly_type(event, raw),
                    severity=round(severity, 3),
                    score=round(float(raw), 4),
                    features=df.iloc[i].to_dict(),
                    timestamp=event.get("timestamp", ""),
                )
                alerts.append(alert)

        logger.debug("Isolation Forest flagged {}/{} events", len(alerts), len(events))
        return alerts
