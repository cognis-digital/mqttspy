"""Core engine for MQTTSPY. Standard library only."""
from __future__ import annotations

import base64
import binascii
import json
import re
from dataclasses import dataclass, field, asdict
from typing import Iterable

# Severity ordering for sorting/exit decisions.
_SEVERITY_RANK = {"high": 3, "medium": 2, "low": 1, "info": 0}

# Packet types that represent a write to the broker.
_WRITE_DIRECTIONS = {"PUBLISH", "PUB", "WRITE"}


@dataclass
class Packet:
    """A single observed MQTT packet from the capture."""

    ts: float | None
    direction: str
    topic: str
    payload: str
    client_id: str = ""
    username: str = ""
    authenticated: bool = True
    retain: bool = False
    qos: int = 0
    line_no: int = 0

    @property
    def is_write(self) -> bool:
        return self.direction.upper() in _WRITE_DIRECTIONS


@dataclass
class TopicStat:
    """Aggregated stats for one topic."""

    topic: str
    messages: int = 0
    writes: int = 0
    retained: int = 0
    publishers: set = field(default_factory=set)
    max_payload: int = 0

    def to_dict(self) -> dict:
        d = asdict(self)
        d["publishers"] = sorted(p for p in self.publishers if p)
        return d


@dataclass
class Finding:
    """A security finding tied to a packet."""

    kind: str
    severity: str
    topic: str
    detail: str
    line_no: int = 0
    evidence: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Report:
    """Full scan result."""

    packets: int
    topics: list[TopicStat]
    findings: list[Finding]
    parse_errors: list[str] = field(default_factory=list)

    @property
    def has_findings(self) -> bool:
        return len(self.findings) > 0

    def to_dict(self) -> dict:
        return {
            "tool": "mqttspy",
            "packets": self.packets,
            "topic_count": len(self.topics),
            "finding_count": len(self.findings),
            "topics": [t.to_dict() for t in self.topics],
            "findings": [f.to_dict() for f in self.findings],
            "parse_errors": self.parse_errors,
        }


# ---------------------------------------------------------------------------
# Parsing
# ---------------------------------------------------------------------------
def parse_capture(text: str) -> tuple[list[Packet], list[str]]:
    """Parse an NDJSON MQTT capture into Packets.

    Returns (packets, parse_errors). Blank lines and lines starting with '#'
    are ignored. Each remaining line must be a JSON object.
    """
    packets: list[Packet] = []
    errors: list[str] = []
    for i, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError as e:
            errors.append(f"line {i}: invalid JSON ({e.msg})")
            continue
        if not isinstance(obj, dict):
            errors.append(f"line {i}: expected JSON object, got {type(obj).__name__}")
            continue
        topic = str(obj.get("topic", "")).strip()
        if not topic:
            errors.append(f"line {i}: missing 'topic'")
            continue
        payload = obj.get("payload", "")
        if not isinstance(payload, str):
            payload = json.dumps(payload, separators=(",", ":"))
        ts = obj.get("ts")
        try:
            ts = float(ts) if ts is not None else None
        except (TypeError, ValueError):
            ts = None
        try:
            qos = int(obj.get("qos", 0) or 0)
        except (TypeError, ValueError):
            qos = 0
            errors.append(f"line {i}: invalid qos value; defaulting to 0")
        packets.append(
            Packet(
                ts=ts,
                direction=str(obj.get("direction", "PUBLISH")),
                topic=topic,
                payload=payload,
                client_id=str(obj.get("client_id", "")),
                username=str(obj.get("username", "")),
                authenticated=bool(obj.get("authenticated", True)),
                retain=bool(obj.get("retain", False)),
                qos=qos,
                line_no=i,
            )
        )
    return packets, errors


# ---------------------------------------------------------------------------
# Topic enumeration
# ---------------------------------------------------------------------------
def enumerate_topics(packets: Iterable[Packet]) -> list[TopicStat]:
    """Aggregate per-topic statistics."""
    stats: dict[str, TopicStat] = {}
    for p in packets:
        st = stats.get(p.topic)
        if st is None:
            st = TopicStat(topic=p.topic)
            stats[p.topic] = st
        st.messages += 1
        if p.is_write:
            st.writes += 1
        if p.retain:
            st.retained += 1
        if p.client_id or p.username:
            st.publishers.add(p.client_id or p.username)
        st.max_payload = max(st.max_payload, len(p.payload))
    return sorted(stats.values(), key=lambda s: (-s.messages, s.topic))


# ---------------------------------------------------------------------------
# Unauthenticated write detection
# ---------------------------------------------------------------------------
def detect_unauth_writes(packets: Iterable[Packet]) -> list[Finding]:
    """Flag any write (PUBLISH) performed by an unauthenticated client.

    Retained unauthenticated writes are escalated to high severity because
    they persist on the broker for every future subscriber.
    """
    findings: list[Finding] = []
    for p in packets:
        if not p.is_write or p.authenticated:
            continue
        who = p.client_id or p.username or "<anonymous>"
        if p.retain:
            sev = "high"
            detail = f"Unauthenticated RETAINED publish by {who} (persists for all subscribers)"
        else:
            sev = "medium"
            detail = f"Unauthenticated publish by {who}"
        findings.append(
            Finding(
                kind="unauth_write",
                severity=sev,
                topic=p.topic,
                detail=detail,
                line_no=p.line_no,
                evidence=_redact(p.payload),
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Secret detection
# ---------------------------------------------------------------------------
# (name, severity, compiled regex). Patterns target high-signal credential
# shapes commonly leaked into IoT payloads/topics.
_SECRET_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    ("aws_access_key", "high", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("private_key_block", "high",
     re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----")),
    ("jwt", "high",
     re.compile(r"\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\b")),
    ("github_token", "high", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36}\b")),
    ("slack_token", "high", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("bearer_token", "high",
     re.compile(r"[Bb]earer\s+[A-Za-z0-9._~+/-]{20,}=*")),
    ("password_field", "medium",
     re.compile(r"(?i)\b(?:password|passwd|pwd|secret|api[_-]?key|apikey|token)\b"
                r"[\"']?\s*[:=]\s*[\"']?([^\s\"',}]{4,})")),
    ("basic_auth_url", "medium",
     re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^\s:@/]+:[^\s:@/]+@")),
    ("private_ipv4", "low",
     re.compile(r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
                r"|192\.168\.\d{1,3}\.\d{1,3}"
                r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b")),
]


def _decoded_variants(payload: str) -> list[str]:
    """Return the raw payload plus a best-effort base64 decode of it.

    IoT devices frequently base64-encode credentials. We try to decode the
    whole payload (a common pattern) so secrets aren't hidden behind a layer.
    """
    variants = [payload]
    s = payload.strip()
    # Only attempt base64 if it looks plausibly like base64 and is non-trivial.
    if len(s) >= 16 and re.fullmatch(r"[A-Za-z0-9+/=\r\n]+", s):
        try:
            decoded = base64.b64decode(s, validate=True)
            text = decoded.decode("utf-8")
            if text and text.isprintable():
                variants.append(text)
        except (binascii.Error, UnicodeDecodeError, ValueError):
            pass
    return variants


def detect_secrets(packets: Iterable[Packet]) -> list[Finding]:
    """Scan payloads (and topics) for credential-shaped secrets."""
    findings: list[Finding] = []
    for p in packets:
        seen: set[tuple[str, str]] = set()
        haystacks = _decoded_variants(p.payload)
        # Topic strings sometimes embed tokens/keys too.
        haystacks.append(p.topic)
        for hay in haystacks:
            for name, sev, pat in _SECRET_PATTERNS:
                m = pat.search(hay)
                if not m:
                    continue
                key = (name, p.topic)
                if key in seen:
                    continue
                seen.add(key)
                matched = m.group(0)
                findings.append(
                    Finding(
                        kind=f"secret:{name}",
                        severity=sev,
                        topic=p.topic,
                        detail=f"Possible {name.replace('_', ' ')} in payload",
                        line_no=p.line_no,
                        evidence=_redact(matched),
                    )
                )
    return findings


def _redact(value: str, keep: int = 4, limit: int = 80) -> str:
    """Mask the middle of a sensitive value while keeping a short prefix."""
    v = value.replace("\n", "\\n").replace("\r", "")
    if len(v) > limit:
        v = v[:limit] + "..."
    if len(v) <= keep + 3:
        return "*" * len(v)
    return v[:keep] + "*" * min(8, len(v) - keep)


# ---------------------------------------------------------------------------
# Top-level scan
# ---------------------------------------------------------------------------
def to_json(report: Report) -> str:
    """Serialise a Report to a JSON string."""
    import json as _json
    return _json.dumps(report.to_dict(), indent=2)


def scan(text: str) -> Report:
    """Run the full MQTT exposure scan on a capture string."""
    if not isinstance(text, str):
        raise TypeError(f"scan() expects a str, got {type(text).__name__}")
    packets, errors = parse_capture(text)
    topics = enumerate_topics(packets)
    findings = detect_unauth_writes(packets) + detect_secrets(packets)
    findings.sort(
        key=lambda f: (-_SEVERITY_RANK.get(f.severity, 0), f.line_no, f.kind)
    )
    return Report(
        packets=len(packets),
        topics=topics,
        findings=findings,
        parse_errors=errors,
    )
