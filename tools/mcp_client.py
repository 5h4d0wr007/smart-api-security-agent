#!/usr/bin/env python3
import os, json, uuid, requests

class PostmanMCP:
    """
    Minimal JSON-RPC client for the Postman MCP FULL server.

    Requires:
      POSTMAN_MCP_URL  (e.g., https://mcp.postman.com/mcp)
      POSTMAN_API_KEY  (API key with access to your workspace)

    Notes:
      - We send BOTH 'Authorization: Bearer' and 'X-API-Key' just to be compatible with
        different gateway configs.
      - We accept 'application/json, text/plain, */*' because the MCP server sometimes wraps
        results as text (e.g., JSON embedded in a 'content' array).
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
            "X-API-Key": self.api_key,
            "Content-Type": "application/json; charset=utf-8",
            "Accept": "application/json, text/plain, */*",
            "User-Agent": "smart-api-security-agent/1.0",
        })

    def _rpc(self, method, params):
        rid = str(uuid.uuid4())
        payload = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}

        # First attempt
        r = self._session.post(self.base_url, data=json.dumps(payload), timeout=self.timeout)

        # If the server does strict negotiation, a 406 can happen; retry with the most permissive Accept
        if r.status_code == 406:
            # retry once without Accept and with */*
            s2 = requests.Session()
            s2.headers.update({
                "Authorization": f"Bearer {self.api_key}",
                "X-API-Key": self.api_key,
                "Content-Type": "application/json; charset=utf-8",
                "Accept": "*/*",
                "User-Agent": "smart-api-security-agent/1.0",
            })
            r = s2.post(self.base_url, data=json.dumps(payload), timeout=self.timeout)

        r.raise_for_status()

        # Some responses are not pure JSON (e.g., text with JSON inside). Try json() first, then manual parse.
        try:
            data = r.json()
        except Exception:
            text = r.text.strip()
            # If plain text came back, surface it clearly for debugging
            raise RuntimeError(f"MCP returned non-JSON (status {r.status_code}): {text[:400]}")

        if "error" in data and data["error"]:
            raise RuntimeError(f"MCP error {data['error'].get('code')}: {data['error'].get('message')}")

        return data.get("result") or data

    # -------- high-level tool wrappers --------

    def call_tool(self, name: str, arguments: dict):
        return self._rpc("tools/call", {"name": name, "arguments": arguments})

    def list_tools(self):
        return self._rpc("tools/list", {})

    def _coerce_text_json(self, raw):
        """
        Many MCP tools return:
          {"content":[{"type":"text","text":"<json or text>"}]}
        Try to parse that text as JSON; if it fails, return {"text": "..."}.
        """
        if isinstance(raw, dict) and "content" in raw:
            for c in raw.get("content") or []:
                if isinstance(c, dict) and c.get("type") == "text":
                    txt = (c.get("text") or "").strip()
                    try:
                        return json.loads(txt)
                    except Exception:
                        return {"text": txt}
        return raw

    # ---- convenience wrappers using camelCase (v2 tools) ----

    def get_workspaces(self):
        out = self.call_tool("getWorkspaces", {})
        return self._coerce_text_json(out)

    def get_collections(self, workspace_id: str):
        out = self.call_tool("getCollections", {"workspace": workspace_id})
        return self._coerce_text_json(out)

    def get_collection(self, collection_id: str):
        out = self.call_tool("getCollection", {"collectionId": collection_id})
        return self._coerce_text_json(out)

    def create_collection(self, workspace_id: str, collection_obj: dict):
        out = self.call_tool("createCollection", {"workspace": workspace_id, "collection": collection_obj})
        return self._coerce_text_json(out)

    def update_collection(self, collection_id: str, collection_obj: dict):
        out = self.call_tool("updateCollection", {"collectionId": collection_id, "collection": collection_obj})
        return self._coerce_text_json(out)

    def get_environments(self, workspace_id: str):
        out = self.call_tool("getEnvironments", {"workspace": workspace_id})
        return self._coerce_text_json(out)

    def create_environment(self, workspace_id: str, name: str, variables: dict):
        out = self.call_tool("createEnvironment", {
            "workspace": workspace_id,
            "environment": {"name": name, "values": [{"key":k,"value":v} for k,v in variables.items()]}
        })
        return self._coerce_text_json(out)

    def update_environment(self, environment_id: str, name: str, variables: dict):
        out = self.call_tool("updateEnvironment", {
            "environmentId": environment_id,
            "environment": {"name": name, "values": [{"key":k,"value":v} for k,v in variables.items()]}
        })
        return self._coerce_text_json(out)

    def upsert_environment(self, workspace_id: str, name: str, variables: dict):
        try:
            return self.create_environment(workspace_id, name, variables)
        except Exception:
            envs = self.get_environments(workspace_id) or {}
            env = next((e for e in (envs.get("environments") or []) if e.get("name") == name), None)
            if not env:
                raise
            return self.update_environment(env["id"], name, variables)
