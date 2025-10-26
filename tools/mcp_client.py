# tools/mcp_client.py
import os, json, uuid, requests

class McpHttp:
    def __init__(self, url: str, api_key: str):
        self.url = url.rstrip("/")
        # IMPORTANT: Streamable HTTP requires Accept to include BOTH JSON & SSE
        self.headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "Authorization": f"Bearer {api_key}",
            # (Optional, but nice) identify your client:
            "User-Agent": "smart-api-security-agent/1.0 (+github-actions)"
        }

    def _rpc(self, method: str, params: dict | None = None):
        payload = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method}
        if params is not None:
            payload["params"] = params
        r = requests.post(self.url, headers=self.headers, data=json.dumps(payload), timeout=60)
        # On success: 200 with JSON body OR 202 with no body (per spec).
        # Postman’s server typically returns 200 JSON for non-streaming tool calls.
        if r.status_code == 202:
            return None
        r.raise_for_status()
        data = r.json()
        if "error" in data:
            raise RuntimeError(f"MCP error {data['error']}")
        return data.get("result")

    def list_tools(self):
        return self._rpc("tools/list", {})

    def call_tool(self, name, arguments: dict):
        return self._rpc("tools/call", {"name": name, "arguments": arguments})
