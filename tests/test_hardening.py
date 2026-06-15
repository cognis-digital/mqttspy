"""Hardening tests: error paths and edge cases for MQTTSPY."""
from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mqttspy.core import scan, parse_capture, to_json
from mqttspy.cli import main


# ---------------------------------------------------------------------------
# CLI error paths
# ---------------------------------------------------------------------------

def test_cli_missing_file_returns_exit2(capsys):
    """Non-existent capture file -> clean stderr message and exit code 2."""
    rc = main(["scan", "definitely_does_not_exist_xyz.ndjson"])
    err = capsys.readouterr().err
    assert rc == 2
    assert "error" in err.lower()
    assert "definitely_does_not_exist_xyz.ndjson" in err


def test_cli_non_utf8_file_returns_exit2(tmp_path, capsys):
    """File with invalid UTF-8 bytes -> clean stderr message and exit code 2."""
    bad = tmp_path / "bad.ndjson"
    bad.write_bytes(b"\xff\xfe not utf-8")
    rc = main(["scan", str(bad)])
    err = capsys.readouterr().err
    assert rc == 2
    assert "error" in err.lower()


# ---------------------------------------------------------------------------
# Parser edge cases
# ---------------------------------------------------------------------------

def test_parse_invalid_qos_is_tolerated():
    """A non-numeric qos field is recovered as 0 with a parse warning."""
    line = json.dumps({"topic": "sensor/data", "payload": "ok", "qos": "fast"})
    packets, errors = parse_capture(line)
    assert len(packets) == 1        # packet is still emitted
    assert packets[0].qos == 0     # defaulted to 0
    assert any("qos" in e for e in errors)  # parse warning recorded


def test_scan_empty_and_comment_only_captures():
    """Empty, whitespace, or comment-only input produces a zero-packet report."""
    empty_cases = [
        "",
        "   ",
        "# only a comment",
        "# comment line 1\n# comment line 2",
    ]
    for text in empty_cases:
        r = scan(text)
        assert r.packets == 0, f"expected 0 packets for {text!r}"
        assert r.findings == []
        assert r.topics == []


# ---------------------------------------------------------------------------
# to_json round-trip
# ---------------------------------------------------------------------------

def test_to_json_round_trips_report():
    """to_json() produces valid JSON that accurately reflects the Report."""
    text = '{"topic":"x/y","payload":"hello","authenticated":false}'
    r = scan(text)
    js = to_json(r)
    obj = json.loads(js)            # must be valid JSON
    assert obj["tool"] == "mqttspy"
    assert obj["packets"] == 1
    assert obj["finding_count"] == len(r.findings)


# ---------------------------------------------------------------------------
# scan() type guard
# ---------------------------------------------------------------------------

def test_scan_type_error_on_non_string():
    """scan() raises TypeError (not AttributeError) when given a non-str."""
    with pytest.raises(TypeError, match=r"scan\(\) expects a str"):
        scan(None)  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        scan(42)    # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# mcp_server import sanity
# ---------------------------------------------------------------------------

def test_mcp_server_importable():
    """mqttspy.mcp_server must be importable (to_json now exists in core)."""
    import importlib
    # This should not raise ImportError for to_json anymore.
    mod = importlib.import_module("mqttspy.mcp_server")
    assert hasattr(mod, "serve")
