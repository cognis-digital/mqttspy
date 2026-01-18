"""MQTTSPY MCP server — exposes scan() as an MCP tool for Cognis.Studio."""
from __future__ import annotations
from mqttspy.core import scan, to_json

def serve() -> int:
    """Start an MCP stdio server. Requires the optional 'mcp' extra:
        pip install "cognis-mqttspy[mcp]"
    """
    try:
        from mcp.server.fastmcp import FastMCP
    except Exception:
        print("Install the MCP extra: pip install 'cognis-mqttspy[mcp]'")
        return 1
    app = FastMCP("mqttspy")

    @app.tool()
    def mqttspy_scan(target: str) -> str:
        """Passively map an MQTT broker: enumerate topics, detect unauthenticated writes, spot PII/secrets in payloads, and emit a risk report.. Returns JSON findings."""
        return to_json(scan(target))

    app.run()
    return 0
