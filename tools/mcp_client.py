# tools/mcp_client.py
import json
import uuid
import requests
from typing import Any, Dict, Optional

class McpHttp:
    """
    Minimal JSON-RPC client for MCP Streamable HTTP.

    - Sends Accept: "application/json, text/event-stream"
    - Parses plain JSON responses
    - Gracefully handles empty bodies (202/204 or 200 with no content)
    - Parses text/event-stream by accumulating 'data:' JSON payload lines
    """
    def __init__(self, url: str, api_key: str, timeout_sec: int = 120):
        self.url = url.rstrip("/")
        self.timeout = timeout_sec
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {api_key}",
            "User-Agent": "smart-api-security-agent/1.0 (+github-actions)"
        }

    def _rpc(self, method: str, params: Optional[Dict[str, Any]] = None) -> Any:
        payload = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method}
        if params is not None:
            payload["params"] = params

        r = requests.post(self.url, headers=self.headers, data=json.dumps(payload), timeout=self.timeout)

        # Some servers reply 202/204 for accepted/no-content
        if r.status_code in (202, 204):
            return None

        # Raise for HTTP errors first (so we can see the status)
        r.raise_for_status()

        # Short-circuit on empty body (legal in some tool calls)
        body = r.text or ""
        if not body.strip():
            return None

        ctype = (r.headers.get("Content-Type") or "").lower()

        # Fast path: JSON
        if "application/json" in ctype:
            try:
                data = r.json()
                if isinstance(data, dict) and "error" in data:
                    raise RuntimeError(f"MCP error {data['error']}")
                if isinstance(data, dict):
                    return data.get("result", data)
                return data
            except json.JSONDecodeError:
                # Fall through to SSE/lenient parsing
                pass

        # SSE path: parse "data: { ... }" lines and take the last JSON object
        if "text/event-stream" in ctype or body.startswith("event:") or "data:" in body:
            last_json = None
            for raw_line in body.splitlines():
                line = raw_line.strip()
                if not line.startswith("data:"):
                    continue
                # Strip leading "data:" and any leading space
                data_str = line[5:].lstrip()
                if not data_str:
                    continue
                try:
                    candidate = json.loads(data_str)
                    # If this looks like a JSON-RPC envelope, unwrap result
                    if isinstance(candidate, dict) and "result" in candidate:
                        last_json = candidate["result"]
                    else:
                        last_json = candidate
                except json.JSONDecodeError:
                    continue
            return last_json

        # Lenient fallback: try to locate a JSON object/array in text
        try:
            return json.loads(body)
        except Exception:
            # As a last resort, just return raw text so caller can decide
            return body

    def list_tools(self) -> Any:
        return self._rpc("tools/list", {})

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        return self._rpc("tools/call", {"name": name, "arguments": arguments})
