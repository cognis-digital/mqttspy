# MQTTSPY — Architecture

> Passively map an MQTT broker: enumerate topics, detect unauthenticated writes, spot PII/secrets in payloads, and emit a risk report.

```
input ──▶ collect ──▶ rules/analyzers ──▶ score ──▶ findings ──▶ table · json
                              │                          │
                         (this repo)                 MCP tool (agents)
```

- **collect** normalizes the target (file/dir/API) into records.
- **rules/analyzers** apply the heuristics shipped in `mqttspy/core.py`.
- **score** ranks by severity.
- **MCP server** (`mqttspy mcp`) exposes `scan` for Cognis.Studio agents.

Extend by adding a rule + a test + a `demos/NN-*/SCENARIO.md`. See [CONTRIBUTING.md](../CONTRIBUTING.md).
