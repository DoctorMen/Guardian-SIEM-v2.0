"""
Guardian SIEM - Detection Validator
====================================
Answers two questions with evidence instead of labels:

1. Does every simulated ATT&CK technique get caught?
   Each atomic test in attack_simulator.py is replayed, as raw unlabeled
   log lines, through the same Detector the dashboard uses. A technique
   counts as detected only if a rule mapped to that technique fires.

2. Do the rules stay quiet on normal activity?
   Every event in config/validation/benign_events.yml (known false-positive
   look-alikes) is replayed the same way. Any alert is a failure.

Usage:
    python detection_validator.py            # print the report
    python detection_validator.py --write    # also refresh docs/detection-coverage.md
                                             # and docs/attack-navigator-layer.json
    python detection_validator.py --check    # exit 1 on a gap, a false positive,
                                             # or stale docs (used in CI)
"""

import argparse
import contextlib
import io
import json
import os
import sys

import yaml

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

from attack_simulator import AttackSimulator  # noqa: E402
from detection_pipeline import Detector  # noqa: E402

BENIGN_PATH = os.path.join(BASE_DIR, "config", "validation", "benign_events.yml")
COVERAGE_MD = os.path.join(BASE_DIR, "docs", "detection-coverage.md")
NAVIGATOR_JSON = os.path.join(BASE_DIR, "docs", "attack-navigator-layer.json")


def _quiet(fn, *args, **kwargs):
    """Engines print on load; keep the report readable."""
    with contextlib.redirect_stdout(io.StringIO()):
        return fn(*args, **kwargs)


def same_technique(a, b):
    """T1059 and T1059.001 are the same technique family; T1059 and T1003 are not."""
    return bool(a) and bool(b) and a.split(".")[0].upper() == b.split(".")[0].upper()


def load_simulator():
    sim = AttackSimulator.__new__(AttackSimulator)
    sim.tests, sim.campaigns, sim.results = {}, {}, []
    sim._register_all_tests()
    return sim


def replay(events):
    """Run events through a fresh Detector; return a list of (event, matches)."""
    detector = _quiet(Detector)
    out = []
    for source, severity, message, _enrichment in events:
        _fields, matches = detector.evaluate(source, message, severity)
        out.append(((source, severity, message), matches))
    return out


def validate_techniques(sim=None):
    sim = sim or load_simulator()
    results = []
    for tid, test in sorted(sim.tests.items()):
        fired = {}
        for _event, matches in replay(test.events):
            for m in matches:
                entry = fired.setdefault(m["rule_name"], {"hits": 0, "mitre_ids": m.get("mitre_ids", [])})
                entry["hits"] += 1
        on_technique = sorted(
            name for name, f in fired.items()
            if any(same_technique(tid, mid) for mid in f["mitre_ids"])
        )
        missing_expected = sorted(set(test.expected_rules) - set(fired))
        results.append({
            "technique_id": tid,
            "technique_name": test.technique_name,
            "tactic": test.tactic,
            "events": len(test.events),
            "rules_fired": sorted(fired),
            "detected_by": on_technique,
            "expected_rules": list(test.expected_rules),
            "missing_expected": missing_expected,
            "status": "DETECTED" if on_technique and not missing_expected else "GAP",
        })
    return results


def unexercised_rules(techniques):
    """Enabled rules that no simulated technique triggers (they need other telemetry)."""
    detector = _quiet(Detector)
    names = [r["name"] for r in detector.rules_engine.rules]
    names += [f"SIGMA: {r.title}" for r in detector.sigma_engine.rules]
    fired = {name for t in techniques for name in t["rules_fired"]}
    return sorted(set(names) - fired)


def load_benign(path=BENIGN_PATH):
    with open(path, encoding="utf-8") as f:
        data = yaml.safe_load(f)
    events = []
    for item in data["events"]:
        msg = " ".join(item["message"].split())
        if "each_ip" in item:
            msgs = [msg.replace("{ip}", ip) for ip in item["each_ip"]]
        elif "each_port" in item:
            msgs = [msg.replace("{port}", str(p)) for p in item["each_port"]]
        elif "each_query" in item:
            msgs = [msg.replace("{query}", q) for q in item["each_query"]]
        else:
            msgs = [msg] * int(item.get("repeat", 1))
        events.append({"why": item["why"], "events": [(item["source"], "INFO", m, {}) for m in msgs]})
    return events


def validate_benign(path=BENIGN_PATH):
    false_positives = []
    groups = load_benign(path)
    for group in groups:
        for (source, _sev, message), matches in replay(group["events"]):
            for m in matches:
                false_positives.append({"why": group["why"], "rule": m["rule_name"], "message": message})
    return {"cases": len(groups), "events": sum(len(g["events"]) for g in groups),
            "false_positives": false_positives}


def coverage_markdown(techniques, benign, unexercised=()):
    detected = sum(1 for t in techniques if t["status"] == "DETECTED")
    lines = [
        "# Detection coverage",
        "",
        "Generated by `python detection_validator.py --write` and checked in CI with `--check`.",
        "Do not edit by hand.",
        "",
        "Each technique's simulated telemetry (raw log lines, no labels) is replayed through the",
        "same detection pipeline the dashboard runs: field extraction, the native YAML rules and",
        "the Sigma rules. A technique counts as detected only when a rule mapped to that ATT&CK",
        "technique fires.",
        "",
        f"**{detected} of {len(techniques)} techniques detected. "
        f"{len(benign['false_positives'])} alerts on {benign['events']} benign look-alike events "
        f"({benign['cases']} cases).**",
        "",
        "| Technique | Name | Tactic | Events | Detected by |",
        "|---|---|---|---|---|",
    ]
    for t in techniques:
        by = ", ".join(t["detected_by"]) if t["detected_by"] else "**GAP**"
        lines.append(f"| {t['technique_id']} | {t['technique_name']} | {t['tactic']} | {t['events']} | {by} |")
    if unexercised:
        lines += [
            "",
            "## Rules with no simulated test yet",
            "",
            "These rules are loaded but no atomic test produces the telemetry they watch for",
            "(packet-rate sensor alerts, web server logs, ...), so nothing above proves them.",
            "",
        ] + [f"- {name}" for name in unexercised]
    lines += [
        "",
        "## Limits",
        "",
        "- The telemetry is synthetic: log lines written to match real Sysmon, Security, PowerShell,",
        "  flow and DNS formats, not recordings from a live attack.",
        "- Thresholds use wall-clock windows, so replay proves the rule logic, not timing behaviour.",
        "- The benign set is small and hand-written; it catches known false-positive patterns, it",
        "  does not measure a false-positive rate.",
        "",
    ]
    return "\n".join(lines)


def navigator_layer(techniques):
    return {
        "name": "Guardian SIEM - validated detections",
        "versions": {"attack": "16", "navigator": "5.1.0", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": "Techniques whose simulated telemetry is caught by Guardian SIEM rules "
                       "(generated by detection_validator.py).",
        "techniques": [
            {
                "techniqueID": t["technique_id"],
                "score": 1 if t["status"] == "DETECTED" else 0,
                "comment": "Detected by: " + (", ".join(t["detected_by"]) or "nothing"),
                "enabled": True,
            }
            for t in techniques
        ],
        "gradient": {"colors": ["#ff6666", "#66bb6a"], "minValue": 0, "maxValue": 1},
        "legendItems": [
            {"label": "Detected", "color": "#66bb6a"},
            {"label": "Gap", "color": "#ff6666"},
        ],
    }


def render_docs(techniques, benign):
    return {
        COVERAGE_MD: coverage_markdown(techniques, benign, unexercised_rules(techniques)),
        NAVIGATOR_JSON: json.dumps(navigator_layer(techniques), indent=2) + "\n",
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--write", action="store_true", help="refresh the generated docs")
    parser.add_argument("--check", action="store_true", help="fail on gaps, false positives or stale docs")
    args = parser.parse_args(argv)

    techniques = validate_techniques()
    benign = validate_benign()

    for t in techniques:
        mark = "PASS" if t["status"] == "DETECTED" else "FAIL"
        print(f"  [{mark}] {t['technique_id']:<10} {t['technique_name']:<45} {', '.join(t['detected_by']) or '-'}")
        if t["missing_expected"]:
            print(f"         expected rules that did not fire: {', '.join(t['missing_expected'])}")
    print(f"\n  Benign look-alikes: {benign['events']} events, {len(benign['false_positives'])} alerts")
    for fp in benign["false_positives"]:
        print(f"  [FP]   {fp['rule']}: {fp['why']}")

    docs = render_docs(techniques, benign)
    if args.write:
        os.makedirs(os.path.dirname(COVERAGE_MD), exist_ok=True)
        for path, content in docs.items():
            with open(path, "w", encoding="utf-8", newline="\n") as f:
                f.write(content)
        print("\n  Wrote " + ", ".join(os.path.relpath(p, BASE_DIR) for p in docs))

    failed = any(t["status"] != "DETECTED" for t in techniques) or benign["false_positives"]
    if args.check:
        for path, content in docs.items():
            current = open(path, encoding="utf-8").read() if os.path.exists(path) else None
            if current != content:
                print(f"\n  {os.path.relpath(path, BASE_DIR)} is stale: run python detection_validator.py --write")
                failed = True
        return 1 if failed else 0
    return 0


if __name__ == "__main__":
    sys.exit(main())
