#!/usr/bin/env python3
import os, json, uuid, requests
from typing import Dict, Any, List

class PostmanMCP:
    """
    Resilient JSON-RPC client for the Postman MCP full server.

    It will automatically try:
      - url permutations: given URL, with/without trailing slash
      - host permutations: US + EU
      - header permutations: Bearer only, X-API-Key only, both
      - content negotiation permutations: Accept & Content-Type combos

    Env:
      POSTMAN_MCP_URL  (optional, defaults to US)
      POSTMAN_API_KEY  (required)
    """

    US_DEFAULT = "https://mcp.postman.com/mcp"
    EU_DEFAULT = "https://mcp.eu.postman.com/mcp"

    def __init__(self, base_url: str | None = None, api_key: str | None = None, timeout: int = 60):
        self.api_key = api_key or os.getenv("POSTMAN_API_KEY") or os.getenv("POSTMAN_API_TOKEN")
        if not self.api_key:
            raise RuntimeError("POSTMAN_API_KEY is required for Postman MCP calls.")

        # Start list of candidate endpoints we will try in order
        env_url = (base_url or os.getenv("POSTMAN_MCP_URL") or "").strip().rstrip("/")
        candidates: List[str] = []
        if env_url:
            candidates.append(env_url)
        candidates.extend([self.US_DEFAULT, self.EU_DEFAULT])

        # normalize and add with/without trailing slash
        urls = []
        for u in candidates:
            u = u.rstrip("/")
            if u not in urls:
                urls.append(u)
            if f"{u}/" not in urls:
                urls.append(f"{u}/")

        self.urls = urls
        self.timeout = timeout

    # ---------- internal permutations ----------

    def _header_permutations(self) -> List[Dict[str, str]]:
        common = {
            "User-Agent": "smart-api-security-agent/1.0",
        }
        return [
            # both
            {
                **common,
                "Authorization": f"Bearer {self.api_key}",
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json, text/plain, */*",
            },
            # bearer only
            {
                **common,
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json, */*",
            },
            # x-api-key only
            {
                **common,
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
                "Accept": "application/json, */*",
            },
            # jsonrpc-ish (some gateways are picky)
            {
                **common,
                "Authorization": f"Bearer {self.api_key}",
                "X-API-Key": self.api_key,
                "Content-Type": "application/json; charset=utf-8",
                "Accept": "*/*",
            },
        ]

    # ---------- core JSON-RPC with retries ----------

    def _rpc(self, url: str, headers: Dict[str, str], method: str, params: Dict[str, Any]):
        rid = str(uuid.uuid4())
        payload = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=self.timeout)

        # Surface useful details on negotiation errors
        if r.status_code == 406:
            raise requests.HTTPError(
                f"406 Not Acceptable from {url} "
                f"(Accept={headers.get('Accept')!r}, Content-Type={headers.get('Content-Type')!r}). "
                f"Body: {r.text[:500]!r}",
                response=r,
            )

        r.raise_for_status()

        try:
            data = r.json()
        except Exception as e:
            raise RuntimeError(
                f"Non-JSON response from {url} (status {r.status_code}): {r.text[:500]!r}"
            ) from e

        if "error" in data and data["error"]:
            err = data["error"]
            raise RuntimeError(f"MCP error {err.get('code')}: {err.get('message')}")

        return data.get("result") or data

    def _rpc_with_fallbacks(self, method: str, params: Dict[str, Any]):
        last_err: Exception | None = None
        for url in self.urls:
            for hdr in self._header_permutations():
                try:
                    return self._rpc(url, hdr, method, params)
                except Exception as e:
                    last_err = e
        # If we get here, all attempts failed
        raise last_err or RuntimeError("MCP call failed after all retries")

    # ---------- public helpers ----------

    def call_tool(self, name: str, arguments: Dict[str, Any]):
        return self._rpc_with_fallbacks("tools/call", {"name": name, "arguments": arguments})

    def list_tools(self):
        return self._rpc_with_fallbacks("tools/list", {})

    def _coerce_text_json(self, raw):
        if isinstance(raw, dict) and "content" in raw:
            for c in raw.get("content") or []:
                if isinstance(c, dict) and c.get("type") == "text":
                    txt = (c.get("text") or "").strip()
                    try:
                        return json.loads(txt)
                    except Exception:
                        return {"text": txt}
        return raw

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
        out = self.call_tool(
            "createEnvironment",
            {
                "workspace": workspace_id,
                "environment": {
                    "name": name,
                    "values": [{"key": k, "value": v} for k, v in variables.items()],
                },
            },
        )
        return self._coerce_text_json(out)

    def update_environment(self, environment_id: str, name: str, variables: dict):
        out = self.call_tool(
            "updateEnvironment",
            {
                "environmentId": environment_id,
                "environment": {
                    "name": name,
                    "values": [{"key": k, "value": v} for k, v in variables.items()],
                },
            },
        )
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
