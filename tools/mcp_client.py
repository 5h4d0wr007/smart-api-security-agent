import os
import json
import time
import uuid
from typing import Any, Dict, Optional, List
import requests


class MCPError(RuntimeError):
    pass


class PostmanMCPClient:
    """
    Minimal JSON-RPC client for Postman MCP with graceful tool fallbacks.

    It supports:
      - getWorkspaces
      - getCollections
      - createCollection
      - (optional) updateCollection (if available)
      - (optional) deleteCollection (if available)

    If updateCollection isn't available, it falls back to createCollection.
    """

    def __init__(self, base_url: Optional[str] = None, api_key: Optional[str] = None, timeout: int = 60):
        self.base_url = (base_url or os.getenv("POSTMAN_MCP_URL") or "").rstrip("/") + "/"
        if not self.base_url.startswith("http"):
            raise ValueError("POSTMAN_MCP_URL must be set to a valid http(s) URL, e.g. https://mcp.postman.com/mcp")
        self.api_key = api_key or os.getenv("POSTMAN_API_KEY")
        if not self.api_key:
            raise ValueError("POSTMAN_API_KEY must be provided (env or argument)")
        self.timeout = timeout
        self._session = requests.Session()
        # Accept both JSON and SSE (some MCP responses stream in text/event-stream)
        self._base_headers = {
            "Authorization": f"Postman-Api-Key {self.api_key}",
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json; charset=utf-8",
        }

    # ---------- low-level RPC helpers ----------

    def _rpc(self, url: str, headers: Dict[str, str], method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """Make a JSON-RPC call. Handles JSON or SSE (text/event-stream) responses."""
        payload = {"jsonrpc": "2.0", "id": str(uuid.uuid4()), "method": method, "params": params}
        r = self._session.post(url, headers=headers, data=json.dumps(payload), timeout=self.timeout)

        # Fast path: normal JSON
        ctype = r.headers.get("Content-Type", "")
        if "application/json" in ctype:
            data = r.json()
            if "error" in data and data["error"]:
                err = data["error"]
                raise MCPError(f"MCP error {err.get('code')}: {err.get('message')}")
            return data.get("result") or {}

        # SSE path: parse last 'data: {...}' event chunk
        if "text/event-stream" in ctype or r.text.startswith("event:"):
            # collect the last 'data: ' JSON we receive
            last_json = None
            for line in r.text.splitlines():
                line = line.strip()
                if line.startswith("data: "):
                    try:
                        last_json = json.loads(line[len("data: "):])
                    except Exception:
                        # ignore malformed interim chunks
                        pass
            if isinstance(last_json, dict):
                if "error" in last_json and last_json["error"]:
                    err = last_json["error"]
                    raise MCPError(f"MCP error {err.get('code')}: {err.get('message')}")
                return last_json.get("result") or {}
            raise RuntimeError(f"Non-JSON SSE body from {url}")

        # Any other content type is unexpected
        raise RuntimeError(
            f"Unexpected response from {url} (status {r.status_code}, Content-Type={ctype}): {r.text[:200]}"
        )

    def _rpc_with_fallbacks(self, method: str, params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Try a few URL variants because some tenants require trailing slash etc.
        """
        last_err = None
        for suffix in ("", "/"):
            url = f"{self.base_url.rstrip('/')}{suffix}"
            try:
                return self._rpc(url, dict(self._base_headers), method, params)
            except Exception as e:
                last_err = e
                # brief backoff in case of transient gateway hiccups
                time.sleep(0.2)
        raise last_err or RuntimeError("MCP call failed after all retries")

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        result = self._rpc_with_fallbacks("tools/call", {"name": name, "arguments": arguments})
        # Most MCP tool responses pack the useful bits in result.content[0].text
        content = result.get("content", [])
        if content and isinstance(content[0], dict) and content[0].get("type") == "text":
            txt = content[0].get("text", "")
            try:
                return json.loads(txt)
            except Exception:
                return txt
        return result

    # ---------- tool wrappers ----------

    def get_workspaces(self) -> Dict[str, Any]:
        return self.call_tool("getWorkspaces", {}) or {}

    def get_collections(self, workspace_id: str) -> Dict[str, Any]:
        return self.call_tool("getCollections", {"workspaceId": workspace_id}) or {}

    def create_collection(self, workspace_id: str, collection_obj: Dict[str, Any]) -> Dict[str, Any]:
        return self.call_tool("createCollection", {"workspaceId": workspace_id, "collection": collection_obj}) or {}

    def delete_collection(self, collection_id: str) -> bool:
        try:
            self.call_tool("deleteCollection", {"collectionId": collection_id})
            return True
        except MCPError:
            return False

    def try_update_collection(self, collection_id: str, collection_obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Attempt update if the tool exists. Return None if tool not found/unsupported.
        """
        try:
            return self.call_tool("updateCollection", {"collectionId": collection_id, "collection": collection_obj})
        except MCPError as e:
            # Tool not found or not supported – report None so caller can fallback.
            msg = str(e).lower()
            if "tool updatecollection not found" in msg or "method not found" in msg or "-32601" in msg:
                return None
            # Other MCP errors should propagate (bad payload, etc.)
            raise

    def upsert_collection(
        self,
        workspace_id: str,
        collection_obj: Dict[str, Any],
        existing_id: Optional[str] = None,
        allow_delete_fallback: bool = True,
    ) -> Dict[str, Any]:
        """
        Preferred entrypoint: updates if possible; otherwise gracefully creates.
        If update isn't supported and create conflicts, optionally deletes then creates.
        """
        if existing_id:
            updated = self.try_update_collection(existing_id, collection_obj)
            if updated is not None:
                return updated

        # No update tool: try create
        try:
            return self.create_collection(workspace_id, collection_obj)
        except MCPError as e:
            # Try a delete+create if create failed due to conflict and we know an existing id
            msg = str(e).lower()
            if existing_id and allow_delete_fallback and ("already exists" in msg or "conflict" in msg):
                if self.delete_collection(existing_id):
                    return self.create_collection(workspace_id, collection_obj)
            # Last resort: rename and create to avoid name collisions
            renamed = collection_obj.copy()
            info = renamed.setdefault("info", {})
            base_name = info.get("name") or "security test collection"
            info["name"] = f"{base_name} (recreated {int(time.time())})"
            return self.create_collection(workspace_id, renamed)
