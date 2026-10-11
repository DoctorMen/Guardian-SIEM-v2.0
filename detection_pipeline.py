"""
Guardian SIEM - Detection Pipeline
===================================
One place where an event is turned into alerts: field extraction, then the
native YAML rules, then Sigma. The dashboard, the demo traffic generator and
the detection validator all call this, so a detection proven in CI is the
same code that runs live.
"""

from field_extractor import extract_fields
from rules_engine import RulesEngine
from sigma_engine import SigmaEngine


class Detector:
    """Runs one event through every detection engine."""

    def __init__(self, rules_path=None, sigma_dir=None, rules_engine=None, sigma_engine=None):
        self.rules_engine = rules_engine or RulesEngine(rules_path)
        self.sigma_engine = sigma_engine or SigmaEngine(sigma_dir)

    def evaluate(self, source, message, severity=""):
        """
        Return (fields, matches) for one event.

        `matches` uses the rules engine's format; Sigma hits are merged in with
        a "SIGMA: " prefix on the rule name.
        """
        fields = extract_fields(source, message)
        matches = self.rules_engine.evaluate(source, message, fields=fields)
        for m in matches:
            m["mitre_ids"] = [m["mitre_id"]] if m.get("mitre_id") else []

        sigma_event = dict(fields)
        sigma_event.update({"source": source, "message": message, "severity": severity})
        for sm in self.sigma_engine.evaluate(sigma_event):
            matches.append({
                "rule_name": f"SIGMA: {sm['rule_name']}",
                "description": sm.get("description", ""),
                "severity": sm["severity"],
                "mitre_id": sm.get("mitre_id", ""),
                "mitre_ids": sm.get("mitre_ids", []),
                "mitre_tactic": sm.get("mitre_tactic", ""),
                "hit_count": 1,
                "threshold": 1,
                "window_seconds": 0,
                "matched_at": sm["matched_at"],
                "source": source,
                "message_excerpt": message[:200],
            })
        return fields, matches


def publish(bus, detector, source, severity, message, enrichment=None):
    """
    Emit a raw event, then one "Alert_<source>" event per rule that fires.

    For producers that run outside the dashboard process (the attack
    simulator), whose events would otherwise never reach the detection
    engines. Returns the matches.
    """
    enrichment = dict(enrichment or {})
    bus.emit(source, severity, message, enrichment=enrichment)
    _fields, matches = detector.evaluate(source, message, severity)
    for match in matches:
        alert = dict(enrichment)
        alert.update({
            "rule_matched": match["rule_name"],
            "mitre_id": match.get("mitre_id", ""),
            "mitre_tactic": match.get("mitre_tactic", ""),
        })
        bus.emit(f"Alert_{source}", match["severity"],
                 f"[{match['rule_name']}] {message[:300]}", enrichment=alert)
    return matches
