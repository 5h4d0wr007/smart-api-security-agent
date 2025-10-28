#!/usr/bin/env python3
import os, json, uuid, requests

class PostmanMCP:
    """
    Tiny JSON-RPC client for the Postman MCP remote server (FULL mode).
    Requires:
      - POSTMAN_MCP_URL (e.g. https://mcp.postman.com/mcp)
      - POSTMAN_API_KEY (Bearer token)
    """

    def __init__(self, base_url=None, api_key=None, timeout=60):
        self.base_url = base_url or os.getenv("POSTMAN_MCP_URL", "https://mcp.postman.com/mcp")
        self.api_key  = api_key  or os.getenv("POSTMAN_API_KEY") or os.getenv("POSTMAN_API_TOKEN")
        if not self.api_key:
            raise RuntimeError("POSTMAN_API_KEY is required to call the Postman MCP server.")
        self.timeout  = timeout
        self._session = requests.Session()
        self._session.headers.update({
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        })

    def _rpc(self, method, params):
        rid = str(uuid.uuid4())
        payload = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        r = self._session.post(self.base_url, data=json.dumps(payload), timeout=self.timeout)
        r.raise_for_status()
        # Some MCP servers return plain text when unhappy — guard JSON parsing:
        try:
            data = r.json()
        except Exception:
            raise RuntimeError(f"MCP returned non-JSON: {r.text[:200]}")
        if "error" in data and data["error"]:
            raise RuntimeError(f"MCP error {data['error'].get('code')}: {data['error'].get('message')}")
        return data.get("result") or data

    # ---- High-level helpers over 'tools/call' ------------------------------

    def call_tool(self, name: str, arguments: dict):
        """Invoke a specific tool by name with arguments."""
        return self._rpc("tools/call", {"name": name, "arguments": arguments})

    def list_tools(self):
        """List available tools (helps debugging FULL vs MINIMAL)."""
        return self._rpc("tools/list", {})

    # ---- Convenience wrappers (arguments match v2 camelCase) ---------------

    def get_workspaces(self):
        # No args; returns content under 'content'[0]['text'] as JSON string (server-dependent)
        out = self.call_tool("getWorkspaces", {})
        return self._coerce_text_json(out)

    def get_collections(self, workspace_id: str):
        out = self.call_tool("getCollections", {"workspace": workspace_id})
        return self._coerce_text_json(out)

    def get_collection(self, collection_id: str):
        out = self.call_tool("getCollection", {"collectionId": collection_id})
        return self._coerce_text_json(out)

    def create_collection(self, workspace_id: str, collection_obj: dict):
        # v2 expects "workspace" (string) and "collection" (object)
        out = self.call_tool("createCollection", {"workspace": workspace_id, "collection": collection_obj})
        return self._coerce_text_json(out)

    def update_collection(self, collection_id: str, collection_obj: dict):
        out = self.call_tool("updateCollection", {"collectionId": collection_id, "collection": collection_obj})
        return self._coerce_text_json(out)

    def upsert_environment(self, workspace_id: str, name: str, variables: dict):
        # If 'createEnvironment' fails due to name collision, try 'getEnvironments' + 'updateEnvironment'
        try:
            created = self.call_tool("createEnvironment", {
                "workspace": workspace_id,
                "environment": {"name": name, "values": [{"key":k,"value":v} for k,v in variables.items()]}
            })
            return self._coerce_text_json(created)
        except Exception:
            envs = self._coerce_text_json(self.call_tool("getEnvironments", {"workspace": workspace_id})) or {}
            env = next((e for e in (envs.get("environments") or []) if e.get("name") == name), None)
            if not env:
                raise
            env_id = env["id"]
            updated = self.call_tool("updateEnvironment", {
                "environmentId": env_id,
                "environment": {"name": name, "values": [{"key":k,"value":v} for k,v in variables.items()]}
            })
            return self._coerce_text_json(updated)

    # ---- Internal: many MCP tools wrap JSON in "content": [{"type":"text","text": "...json..."}]
    def _coerce_text_json(self, raw):
        if isinstance(raw, dict) and "content" in raw:
            chunks = raw.get("content") or []
            for c in chunks:
                if isinstance(c, dict) and c.get("type") == "text":
                    txt = c.get("text", "").strip()
                    try:
                        return json.loads(txt)
                    except Exception:
                        # Some tools return non-JSON summaries; in that case, return text.
                        return {"text": txt}
        return raw
