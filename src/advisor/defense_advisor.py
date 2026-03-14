"""
Adaptive Defense Recommendation System
Suggests context-aware mitigations based on risk scores and attack chains.
"""

from typing import List, Dict
from loguru import logger


RECOMMENDATIONS_MAP = [
    {
        "condition": lambda score, chain, priv: score >= 80,
        "action": "enforce_mfa",
        "label": "Enforce Multi-Factor Authentication",
        "severity": "CRITICAL",
        "details": "Risk score is critically high. Immediately enforce MFA for this entity.",
    },
    {
        "condition": lambda score, chain, priv: chain and "Lateral Movement" in chain.get("chain_label", ""),
        "action": "isolate_endpoint",
        "label": "Isolate Endpoint from Network",
        "severity": "CRITICAL",
        "details": "Lateral movement detected. Immediately isolate the device from the network.",
    },
    {
        "condition": lambda score, chain, priv: score >= 60,
        "action": "force_password_reset",
        "label": "Force Password Reset",
        "severity": "HIGH",
        "details": "Elevated risk score indicates possible credential compromise.",
    },
    {
        "condition": lambda score, chain, priv: chain and "Data Exfiltration" in chain.get("chain_label", ""),
        "action": "block_session",
        "label": "Block Active Session & Flag for Review",
        "severity": "CRITICAL",
        "details": "Data exfiltration pattern detected. Terminate all active sessions immediately.",
    },
    {
        "condition": lambda score, chain, priv: score >= 50 and priv >= 3,
        "action": "reduce_privileges",
        "label": "Revoke Elevated Privileges Temporarily",
        "severity": "HIGH",
        "details": "High-risk entity holds elevated privileges. Temporarily downgrade access.",
    },
    {
        "condition": lambda score, chain, priv: score >= 35,
        "action": "increase_monitoring",
        "label": "Increase Monitoring & Logging Level",
        "severity": "MEDIUM",
        "details": "Moderate risk detected. Enable verbose logging and increase alert sensitivity.",
    },
    {
        "condition": lambda score, chain, priv: score >= 40,
        "action": "patch_prioritization",
        "label": "Prioritize Vulnerability Patching",
        "severity": "MEDIUM",
        "details": "Active risk signals suggest unpatched services may be exploited. Accelerate patch deployment.",
    },
]


class DefenseAdvisor:
    """
    Context-aware defense recommendation engine.
    Maps risk scores and attack chain signals to actionable mitigations.
    """

    def recommend(
        self,
        risk_scores: List[Dict],
        chains: List[Dict],
        privacy_alerts: List[Dict],
    ) -> List[Dict]:
        """Generate prioritized recommendations for all high-risk entities."""

        # Index chains by entity for fast lookup
        chain_by_entity: Dict[str, Dict] = {}
        for chain in chains:
            entity = chain["entity"]
            # Keep the highest-severity chain per entity
            if entity not in chain_by_entity or chain["max_severity"] > chain_by_entity[entity]["max_severity"]:
                chain_by_entity[entity] = chain

        recommendations = []

        for rs in risk_scores:
            entity = rs["entity"]
            score  = rs["score"]
            priv   = rs.get("privilege_level", 1)
            chain  = chain_by_entity.get(entity)

            entity_recs = []
            seen_actions = set()

            for rule in RECOMMENDATIONS_MAP:
                try:
                    if rule["condition"](score, chain, priv) and rule["action"] not in seen_actions:
                        seen_actions.add(rule["action"])
                        entity_recs.append({
                            "action":   rule["action"],
                            "label":    rule["label"],
                            "severity": rule["severity"],
                            "details":  rule["details"],
                        })
                except Exception:
                    continue

            if entity_recs:
                recommendations.append({
                    "entity":          entity,
                    "entity_type":     rs["entity_type"],
                    "risk_score":      score,
                    "risk_level":      rs["risk_level"],
                    "attack_chain":    chain["chain_label"] if chain else None,
                    "actions":         entity_recs,
                    "action_count":    len(entity_recs),
                })

        # Sort by risk score descending
        recommendations.sort(key=lambda x: x["risk_score"], reverse=True)
        logger.debug("Generated {} recommendation bundles", len(recommendations))
        return recommendations
