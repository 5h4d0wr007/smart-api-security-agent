# tools/mcp_client.py
import os
import json
import time
from typing import Any, Dict, Optional

import requests


class MCPClientError(RuntimeError):
    pass


class PostmanMCPClient:
    def __init__(self,
                 base_url: Optional[str] = None,
                 api_key: Optional[str] = None,
                 timeout: int = 60):
        self.base_url = (base_url or os.getenv("POSTMAN_MCP_URL") or "https://mcp.postman.com/mcp").rstrip("/") + "/"
        self.api_key = api_key or os.getenv("POSTMAN_API_KEY") or ""
        if not self.api_key:
            raise MCPClientError("POSTMAN_API_KEY is not set")

        # Headers MCP expects; include the API key in multiple forms.
        self._base_headers = {
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json, text/event-stream",
            "x-api-key": self.api_key,
            "X-API-Key": self.api_key,
            "X-Postman-API-Key": self.api_key,
            "Authorization": f"Bearer {self.api_key}",
            "User-Agent": "smart-api-security-agent/1.0",
        }
        self.timeout = timeout

    # -------- JSON-RPC transport (compatible with your previous code) --------

    def _rpc_with_fallbacks(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        # Single attempt (kept name so existing calls work)
        return self._rpc(self.base_url, self._base_headers, method, params)

    def _rpc(self, url: str, headers: Dict[str, str], method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        payload = {"jsonrpc": "2.0", "id": int(time.time() * 1000), "method": method, "params": params}
        r = requests.post(url, data=json.dumps(payload), headers=headers, timeout=self.timeout)

        ctype = r.headers.get("Content-Type", "")
        body = r.text

        # JSON
        if "application/json" in ctype:
            data = r.json()
        # SSE (JSON in data: lines)
        elif "text/event-stream" in ctype or body.startswith("event:"):
            data = self._parse_sse(body)
        else:
            # Try parse anyway; else helpful error
            try:
                data = r.json()
            except Exception:
                raise MCPClientError(f"Non-JSON response (status {r.status_code}): {body[:200]}")

        if "error" in data:
            err = data["error"]
            raise MCPClientError(f"MCP error {err.get('code')}: {err.get('message')}")
        return data.get("result", {})

    @staticmethod
    def _parse_sse(text: str) -> Dict[str, Any]:
        last = None
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                chunk = line[len("data:"):].strip()
                if chunk:
                    try:
                        last = json.loads(chunk)
                    except Exception:
                        pass
        if last is None:
            raise MCPClientError("SSE stream contained no JSON data frames")
        # Some gateways nest result under 'result'
        return last.get("result", last)

    # -------- Tool wrappers (names unchanged) --------

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self._rpc_with_fallbacks("tools/call", {"name": name, "arguments": arguments})

    def get_workspaces(self) -> Dict[str, Any]:
        return self.call_tool("getWorkspaces", {})

    def get_collections(self, workspace_id: str) -> Dict[str, Any]:
        return self.call_tool("getCollections", {"workspaceId": workspace_id})

    def create_collection(self, workspace_id: str, collection_obj: Dict[str, Any]) -> Dict[str, Any]:
        return self.call_tool("createCollection", {"workspaceId": workspace_id, "collection": collection_obj})

    # Keep your code that *uses* update if it exists server-side; otherwise use create.
    def create_or_update_collection(self, workspace_id: str, name: str, collection_obj: Dict[str, Any]) -> Dict[str, Any]:
        cols = self.get_collections(workspace_id).get("collections", [])
        existing = next((c for c in cols if c.get("name") == name), None)
        if existing:
            try:
                # Only call if tool exists
                return self.call_tool("updateCollection", {"collectionId": existing["id"], "collection": collection_obj})
            except MCPClientError:
                # Fallback: delete+create if update isn't supported
                try:
                    self.call_tool("deleteCollection", {"collectionId": existing["id"]})
                except MCPClientError:
                    pass
        return self.create_collection(workspace_id, collection_obj)
