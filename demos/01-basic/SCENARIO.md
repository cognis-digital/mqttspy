# Demo 01 - Basic MQTT exposure scan

This demo runs MQTTSPY against a small captured MQTT session
(`capture.ndjson`) representing a home/IoT broker.

## What the capture contains

- A handful of normal, authenticated `home/...` telemetry publishes.
- An **unauthenticated retained publish** to `home/cmd/door` (an anonymous
  client setting a retained command - high severity, persists for everyone).
- An **unauthenticated publish** to `home/light` (medium severity).
- A payload containing a **password field** (`{"user":"admin","password":...}`).
- A payload containing an **AWS access key**.
- A payload that is **base64-encoded** and decodes to a `Bearer` token,
  proving MQTTSPY decodes base64 before scanning.
- Two comment/blank lines and one malformed JSON line to exercise the
  parser's error reporting.

## Run it

```bash
python -m mqttspy scan demos/01-basic/capture.ndjson
# JSON form for CI:
python -m mqttspy scan demos/01-basic/capture.ndjson --format json
```

## Expected result

- Several topics enumerated (`home/temp`, `home/light`, `home/cmd/door`, ...).
- At least these findings:
  - `unauth_write` **high** on `home/cmd/door` (retained, anonymous).
  - `unauth_write` **medium** on `home/light`.
  - `secret:password_field` on the credentials payload.
  - `secret:aws_access_key` **high**.
  - `secret:bearer_token` recovered from the base64 payload.
- One parse warning for the malformed JSON line.
- **Exit code 1** (findings present) - suitable as a CI gate.
