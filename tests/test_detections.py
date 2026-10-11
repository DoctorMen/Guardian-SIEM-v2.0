"""
Detection-as-code tests.

Every simulated ATT&CK technique must be caught by a rule mapped to that
technique, and no rule may fire on the benign look-alike events in
config/validation/benign_events.yml. Telemetry is replayed through the same
Detector the dashboard uses.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import detection_validator as dv  # noqa: E402
from detection_validator import _quiet  # noqa: E402
from detection_pipeline import Detector  # noqa: E402

SIM = dv.load_simulator()
TECHNIQUES = {t["technique_id"]: t for t in dv.validate_techniques(SIM)}
BENIGN = dv.load_benign()


@pytest.mark.parametrize("technique_id", sorted(TECHNIQUES))
def test_technique_is_detected(technique_id):
    result = TECHNIQUES[technique_id]
    assert result["detected_by"], f"{technique_id}: no rule mapped to this technique fired; fired={result['rules_fired']}"
    assert not result["missing_expected"], f"{technique_id}: expected rules did not fire: {result['missing_expected']}"


@pytest.mark.parametrize("case", BENIGN, ids=[c["why"][:60] for c in BENIGN])
def test_benign_look_alike_is_quiet(case):
    alerts = [m["rule_name"] for _event, matches in dv.replay(case["events"]) for m in matches]
    assert alerts == [], f"false positive on: {case['why']}"


def test_generated_docs_are_current():
    techniques = list(TECHNIQUES.values())
    benign = dv.validate_benign()
    for path, content in dv.render_docs(techniques, benign).items():
        with open(path, encoding="utf-8") as f:
            assert f.read() == content, f"{path} is stale: run python detection_validator.py --write"


def test_telemetry_alone_decides_detection():
    """Stripping the simulator's events down to (source, message) loses nothing the engines need."""
    events = SIM.tests["T1003"].events
    bare = [(src, "INFO", msg, {}) for src, _sev, msg, _enr in events]
    fired = {m["rule_name"] for _e, ms in dv.replay(bare) for m in ms}
    assert "SIGMA: LSASS Memory Access - Credential Dumping" in fired


def _failed_logon(ip):
    return ("Windows_EventLog",
            f"Event ID 4625: An account failed to log on. Logon Type: 3. Source Network Address: {ip}")


def test_brute_force_counts_per_source_address():
    detector = _quiet(Detector)
    spread = [detector.evaluate(*_failed_logon(f"10.0.0.{i}"))[1] for i in range(1, 9)]
    assert not any(m["rule_name"] == "Brute Force Detection" for ms in spread for m in ms)

    one_source = [detector.evaluate(*_failed_logon("203.0.113.7"))[1] for _ in range(5)]
    assert any(m["rule_name"] == "Brute Force Detection" for m in one_source[-1])


def test_lsass_rule_ignores_query_only_access():
    detector = _quiet(Detector)
    base = ("Event ID 10: Process accessed. SourceImage: C:\\Users\\Public\\x.exe. "
            "TargetImage: C:\\Windows\\System32\\lsass.exe. GrantedAccess: {}")
    _f, read = detector.evaluate("Windows_Sysmon", base.format("0x1010"))
    _f, query = detector.evaluate("Windows_Sysmon", base.format("0x1000"))
    assert "SIGMA: LSASS Memory Access - Credential Dumping" in {m["rule_name"] for m in read}
    assert query == []


def test_masqueraded_svchost_is_not_filtered():
    """The svchost filter matches the real System32 path only."""
    detector = _quiet(Detector)
    _f, matches = detector.evaluate(
        "Windows_Sysmon",
        "Event ID 10: Process accessed. SourceImage: C:\\ProgramData\\svchost.exe. "
        "TargetImage: C:\\Windows\\System32\\lsass.exe. GrantedAccess: 0x1410",
    )
    assert "SIGMA: LSASS Memory Access - Credential Dumping" in {m["rule_name"] for m in matches}
