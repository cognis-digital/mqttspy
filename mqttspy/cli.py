"""Command-line interface for MQTTSPY."""
from __future__ import annotations

import argparse
import json
import sys

from . import TOOL_NAME, TOOL_VERSION
from .core import scan, Report

_EXAMPLES = """
examples:
  # Scan a capture and print a human-readable table
  mqttspy scan capture.ndjson

  # Emit JSON for CI / piping (exit code is non-zero if findings exist)
  mqttspy scan capture.ndjson --format json | jq '.findings'

  # Read the capture from stdin
  cat capture.ndjson | mqttspy scan -

capture format (NDJSON, one packet per line):
  {"ts":1700000000,"direction":"PUBLISH","topic":"home/light",
   "payload":"on","client_id":"abc","authenticated":true,"retain":false}

exit codes:
  0  scan completed, no findings
  1  scan completed, one or more findings (use for CI gates)
  2  usage / input error
"""


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Analyze an MQTT capture: enumerate topics, detect "
        "unauthenticated writes, and spot secrets in payloads.",
        epilog=_EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version",
        version=f"{TOOL_NAME} {TOOL_VERSION}",
    )
    sub = parser.add_subparsers(dest="command", metavar="command")

    scan_p = sub.add_parser(
        "scan",
        help="scan an MQTT capture file for exposure",
        description="Scan an NDJSON MQTT capture for topic exposure, "
        "unauthenticated writes, and leaked secrets.",
    )
    scan_p.add_argument(
        "capture",
        help="path to NDJSON capture file, or '-' for stdin",
    )
    scan_p.add_argument(
        "--format", choices=("table", "json"), default="table",
        help="output format (default: table)",
    )
    scan_p.add_argument(
        "--fail-on", choices=("any", "high", "medium", "never"), default="any",
        help="minimum severity that triggers a non-zero exit (default: any)",
    )
    return parser


_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3}


def _should_fail(report: Report, fail_on: str) -> bool:
    if fail_on == "never":
        return False
    if not report.findings:
        return False
    if fail_on == "any":
        return True
    threshold = _RANK[fail_on]
    return any(_RANK.get(f.severity, 0) >= threshold for f in report.findings)


def _read_capture(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _render_table(report: Report) -> str:
    lines: list[str] = []
    lines.append(f"MQTTSPY scan: {report.packets} packets, "
                 f"{len(report.topics)} topics, "
                 f"{len(report.findings)} findings")
    lines.append("")
    lines.append("TOPICS")
    lines.append("-" * 60)
    if report.topics:
        lines.append(f"{'topic':<34} {'msgs':>5} {'wr':>4} {'ret':>4} {'pub':>4}")
        for t in report.topics:
            topic = t.topic if len(t.topic) <= 34 else t.topic[:31] + "..."
            lines.append(
                f"{topic:<34} {t.messages:>5} {t.writes:>4} "
                f"{t.retained:>4} {len(t.publishers):>4}"
            )
    else:
        lines.append("(none)")
    lines.append("")
    lines.append("FINDINGS")
    lines.append("-" * 60)
    if report.findings:
        for f in report.findings:
            lines.append(f"[{f.severity.upper():<6}] {f.kind}  (line {f.line_no})")
            lines.append(f"         topic: {f.topic}")
            lines.append(f"         {f.detail}")
            if f.evidence:
                lines.append(f"         evidence: {f.evidence}")
    else:
        lines.append("(no findings) - capture looks clean")
    if report.parse_errors:
        lines.append("")
        lines.append("PARSE WARNINGS")
        lines.append("-" * 60)
        for e in report.parse_errors:
            lines.append(f"  {e}")
    return "\n".join(lines)


def main(argv=None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.command is None:
        parser.print_help()
        return 2

    if args.command == "scan":
        try:
            text = _read_capture(args.capture)
        except OSError as e:
            print(f"{TOOL_NAME}: error: cannot read {args.capture!r}: {e}",
                  file=sys.stderr)
            return 2

        report = scan(text)

        if args.format == "json":
            print(json.dumps(report.to_dict(), indent=2))
        else:
            print(_render_table(report))

        return 1 if _should_fail(report, args.fail_on) else 0

    parser.print_help()
    return 2
