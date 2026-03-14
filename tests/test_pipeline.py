"""
Unit tests for the Cyber Risk Intelligence Platform
"""

import pytest
from src.detection.anomaly_detector import AnomalyDetector
from src.scoring.risk_scorer import RiskScorer
from src.correlation.chain_builder import AttackChainBuilder
from src.privacy.privacy_monitor import PrivacyMonitor
from src.advisor.defense_advisor import DefenseAdvisor


SAMPLE_EVENTS = [
    {
        "id": "evt_001", "timestamp": "2024-03-14T02:15:00",
        "user": "attacker", "device": "ws-001", "entity_type": "user",
        "failed_logins_1h": 9, "unique_ips_accessed": 22,
        "data_transferred_mb": 450, "off_hours": True, "new_device": True,
        "privilege_level": 4, "api_calls_per_min": 110, "lateral_hops": 3,
        "historical_incidents": 2,
    },
    {
        "id": "evt_002", "timestamp": "2024-03-14T09:10:00",
        "user": "normal_user", "device": "ws-010", "entity_type": "user",
        "failed_logins_1h": 0, "unique_ips_accessed": 2,
        "data_transferred_mb": 5, "off_hours": False, "new_device": False,
        "privilege_level": 1, "api_calls_per_min": 2, "lateral_hops": 0,
        "historical_incidents": 0,
    },
]


class TestAnomalyDetector:
    def test_returns_list(self):
        detector = AnomalyDetector()
        result = detector.detect(SAMPLE_EVENTS)
        assert isinstance(result, list)

    def test_empty_input(self):
        detector = AnomalyDetector()
        result = detector.detect([])
        assert result == []

    def test_anomaly_has_required_fields(self):
        detector = AnomalyDetector()
        results = detector.detect(SAMPLE_EVENTS)
        for alert in results:
            assert hasattr(alert, "entity")
            assert hasattr(alert, "severity")
            assert hasattr(alert, "anomaly_type")
            assert 0.0 <= alert.severity <= 1.0


class TestRiskScorer:
    def test_scores_computed(self):
        scorer = RiskScorer()
        scores = scorer.score(SAMPLE_EVENTS, [])
        assert len(scores) > 0

    def test_score_range(self):
        scorer = RiskScorer()
        scores = scorer.score(SAMPLE_EVENTS, [])
        for s in scores:
            assert 0 <= s["score"] <= 100

    def test_risk_levels_valid(self):
        scorer = RiskScorer()
        scores = scorer.score(SAMPLE_EVENTS, [])
        valid_levels = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
        for s in scores:
            assert s["risk_level"] in valid_levels


class TestPrivacyMonitor:
    def test_bulk_download_flagged(self):
        monitor = PrivacyMonitor()
        events = [{
            "id": "e1", "user": "u1", "timestamp": "",
            "data_transferred_mb": 500, "off_hours": False,
            "new_device": False, "privilege_level": 1,
            "api_calls_per_min": 5, "lateral_hops": 0,
        }]
        alerts = monitor.analyze(events)
        rule_ids = [a["rule_id"] for a in alerts]
        assert "PRIV-001" in rule_ids

    def test_clean_event_no_alerts(self):
        monitor = PrivacyMonitor()
        events = [{
            "id": "e2", "user": "u2", "timestamp": "",
            "data_transferred_mb": 10, "off_hours": False,
            "new_device": False, "privilege_level": 1,
            "api_calls_per_min": 3, "lateral_hops": 0,
        }]
        alerts = monitor.analyze(events)
        assert len(alerts) == 0


class TestDefenseAdvisor:
    def test_critical_score_triggers_mfa(self):
        advisor = DefenseAdvisor()
        risk_scores = [{"entity": "attacker", "entity_type": "user", "score": 90, "risk_level": "CRITICAL"}]
        recs = advisor.recommend(risk_scores, [], [])
        assert len(recs) > 0
        actions = [a["action"] for a in recs[0]["actions"]]
        assert "enforce_mfa" in actions

    def test_low_score_no_critical_actions(self):
        advisor = DefenseAdvisor()
        risk_scores = [{"entity": "safe_user", "entity_type": "user", "score": 10, "risk_level": "LOW"}]
        recs = advisor.recommend(risk_scores, [], [])
        assert len(recs) == 0
