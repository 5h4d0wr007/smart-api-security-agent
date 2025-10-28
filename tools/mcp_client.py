# tools/mcp_client.py
import os
import time
import json
from typing import Any, Dict, Optional

import requests


class MCPClientError(RuntimeError):
    pass


class PostmanMCPClient:
    """
    Minimal JSON-RPC client for Postman MCP (HTTP endpoint).
    Works with JSON responses and JSON over Server-Sent Events.
    """

    def __init__(self,
                 base_url: Optional[str] = None,
                 api_key: Optional[str] = None,
                 timeout: int = 60):
        # Prefer repo variable, fall back to env
        self.base_url = (base_url
                         or os.getenv("POSTMAN_MCP_URL")
                         or "https://mcp.postman.com/mcp").rstrip("/") + "/"
        self.api_key = api_key or os.getenv("POSTMAN_API_KEY") or ""
        self.timeout = timeout

        # Build headers once; include all common key headers
        self._base_headers = {
            "Content-Type": "application/json; charset=utf-8",
            # MCP uses JSON and can stream via SSE; advertise both
            "Accept": "application/json, text/event-stream",
            "User-Agent": "smart-api-security-agent/1.0",
        }

        if not self.api_key:
            raise MCPClientError(
                "POSTMAN_API_KEY not set. Add it as a repository Secret named "
                "'POSTMAN_API_KEY' and pass it to the job step env."
            )

        # Provide the API key in multiple, commonly accepted forms.
        # The server will accept one or more of these.
        key = self.api_key
        self._base_headers.update({
            "x-api-key": key,
            "X-API-Key": key,
            "X-Postman-API-Key": key,
            "Authorization": f"Bearer {key}",
        })

    # ---------- low-level RPC ----------

    def _rpc(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform a JSON-RPC call. Supports JSON responses and JSON chunks sent
        via text/event-stream. Raises MCPClientError on protocol/server errors.
        """
        url = self.base_url
        payload = {"jsonrpc": "2.0", "id": int(time.time() * 1000), "method": method, "params": params}

        r = requests.post(url,
                          data=json.dumps(payload),
                          headers=self._base_headers,
                          timeout=self.timeout)

        # Some deployments send JSON in SSE frames (text/event-stream) even with 200 OK.
        ctype = r.headers.get("Content-Type", "")
        if "application/json" in ctype:
            data = r.json()
        elif "text/event-stream" in ctype or r.text.startswith("event:"):
            # Extract last JSON 'data:' line we received.
            data = self._parse_sse_json(r.text)
        else:
            # Try to parse JSON anyway; if it fails, raise a helpful error.
            try:
                data = r.json()
            except Exception:
                raise MCPClientError(
                    f"Non-JSON response from {url} (status {r.status_code}): {r.text[:200]}"
                )

        if "error" in data:
            err = data["error"]
            raise MCPClientError(f"MCP error {err.get('code')}: {err.get('message')}")

        return data.get("result", {})

    @staticmethod
    def _parse_sse_json(text: str) -> Dict[str, Any]:
        """
        Very small SSE parser: looks for the last 'data: { ... }' JSON object.
        """
        last_json = None
        for line in text.splitlines():
            if line.startswith("data:"):
                chunk = line[len("data:"):].strip()
                if chunk:
                    try:
                        obj = json.loads(chunk)
                        last_json = obj
                    except Exception:
                        # ignore non-JSON data lines
                        pass
        if last_json is None:
            raise MCPClientError("SSE stream contained no JSON 'data:' frames")
        # JSON-RPC result may be nested under 'result'
        return last_json.get("result", last_json)

    # ---------- high-level helpers (tool wrappers) ----------

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        return self._rpc("tools/call", {"name": name, "arguments": arguments})

    def get_workspaces(self) -> Dict[str, Any]:
        # returns: { "workspaces": [...] }
        return self.call_tool("getWorkspaces", {})

    def get_collections(self, workspace_id: str) -> Dict[str, Any]:
        # returns: { "collections": [...] }
        return self.call_tool("getCollections", {"workspaceId": workspace_id})

    def create_collection(self, workspace_id: str, collection_obj: Dict[str, Any]) -> Dict[str, Any]:
        # returns the created collection metadata (id, name, etc.)
        return self.call_tool("createCollection", {
            "workspaceId": workspace_id,
            "collection": collection_obj
        })

    def create_or_update_collection(self, workspace_id: str, name: str, collection_obj: Dict[str, Any]) -> Dict[str, Any]:
        """
        If a collection with 'name' exists in the workspace, delete it then create a fresh one.
        (Some MCP deployments expose only create/list; this is a safe upsert.)
        """
        cols = self.get_collections(workspace_id).get("collections", [])
        existing = next((c for c in cols if c.get("name") == name), None)
        if existing:
            # If server has delete tool, use it; otherwise create another copy with unique name.
            try:
                self.call_tool("deleteCollection", {"collectionId": existing["id"]})
            except MCPClientError:
                pass
        return self.create_collection(workspace_id, collection_obj)
