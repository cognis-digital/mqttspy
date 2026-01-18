"""Smoke tests for MQTTSPY. No network access."""
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mqttspy import (
    TOOL_NAME,
    TOOL_VERSION,
    scan,
    parse_capture,
    enumerate_topics,
    detect_unauth_writes,
    detect_secrets,
)
from mqttspy.cli import main

DEMO = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "demos", "01-basic", "capture.ndjson",
)


def _load_demo():
    with open(DEMO, "r", encoding="utf-8") as fh:
        return fh.read()


def test_metadata():
    assert TOOL_NAME == "mqttspy"
    assert TOOL_VERSION.count(".") == 2


def test_parse_skips_comments_and_records_errors():
    packets, errors = parse_capture(_load_demo())
    # 8 valid packet lines in the demo.
    assert len(packets) == 8
    # The 'this is not valid json' line is reported.
    assert any("invalid JSON" in e for e in errors)
    assert len(errors) == 1


def test_topic_enumeration():
    packets, _ = parse_capture(_load_demo())
    topics = enumerate_topics(packets)
    names = {t.topic for t in topics}
    assert "home/temp" in names
    assert "home/cmd/door" in names
    # home/temp has the most messages (2).
    top = topics[0]
    assert top.topic == "home/temp"
    assert top.messages == 2


def test_unauth_write_detection():
    packets, _ = parse_capture(_load_demo())
    findings = detect_unauth_writes(packets)
    kinds = {(f.topic, f.severity) for f in findings}
    # Retained anonymous write is high severity.
    assert ("home/cmd/door", "high") in kinds
    # Non-retained unauthenticated write is medium.
    assert ("home/light", "medium") in kinds
    # Authenticated writes are NOT flagged.
    assert all(f.topic not in ("home/temp",) for f in findings)


def test_secret_detection_and_base64_decode():
    packets, _ = parse_capture(_load_demo())
    findings = detect_secrets(packets)
    kinds = {f.kind for f in findings}
    assert "secret:password_field" in kinds
    assert "secret:aws_access_key" in kinds
    # Bearer token was hidden behind base64 and must be recovered.
    assert "secret:bearer_token" in kinds
    # Evidence is redacted (not the full raw secret).
    aws = next(f for f in findings if f.kind == "secret:aws_access_key")
    assert "AKIAIOSFODNN7EXAMPLE" not in aws.evidence
    assert "*" in aws.evidence


def test_scan_report_and_exit_logic():
    report = scan(_load_demo())
    assert report.packets == 8
    assert report.has_findings
    # Findings sorted by severity desc -> first is high.
    assert report.findings[0].severity == "high"
    d = report.to_dict()
    assert d["tool"] == "mqttspy"
    assert d["finding_count"] == len(report.findings)


def test_clean_capture_has_no_findings():
    clean = (
        '{"topic":"home/temp","payload":"21.5","authenticated":true}\n'
        '{"topic":"home/temp","payload":"21.6","authenticated":true}\n'
    )
    report = scan(clean)
    assert report.packets == 2
    assert not report.has_findings


def test_cli_json_exit_nonzero_on_findings(capsys):
    rc = main(["scan", DEMO, "--format", "json"])
    out = capsys.readouterr().out
    assert rc == 1  # findings present -> CI gate trips
    assert '"tool": "mqttspy"' in out
    assert '"findings"' in out


def test_cli_table_output(capsys):
    rc = main(["scan", DEMO])
    out = capsys.readouterr().out
    assert rc == 1
    assert "TOPICS" in out
    assert "FINDINGS" in out


def test_cli_fail_on_never_returns_zero():
    rc = main(["scan", DEMO, "--fail-on", "never"])
    assert rc == 0


def test_cli_fail_on_high_with_clean_high(tmp_path):
    # Capture with only a low-severity finding (private IP) -> fail-on high = 0.
    p = tmp_path / "cap.ndjson"
    p.write_text(
        '{"topic":"net/info","payload":"host 192.168.1.5","authenticated":true}\n',
        encoding="utf-8",
    )
    rc = main(["scan", str(p), "--fail-on", "high"])
    assert rc == 0
    rc_any = main(["scan", str(p), "--fail-on", "any"])
    assert rc_any == 1


def test_cli_no_command_returns_usage():
    assert main([]) == 2


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
