#!/usr/bin/env python3
import os
import json
import uuid
import requests
from typing import Dict, Any, List


class PostmanMCP:
    """
    Resilient JSON-RPC client for the Postman MCP full server (US region only).

    Behavior:
      - Uses US URL only (default https://mcp.postman.com/mcp), or POSTMAN_MCP_URL if provided.
      - Tries with and without trailing slash.
      - Tries header permutations (Bearer only, X-API-Key only, both).
      - Sets Accept to *application/json, text/event-stream* (required by server).
      - Detects and parses SSE (text/event-stream) responses.
      - Surfaces useful response body excerpts on errors.

    Env:
      POSTMAN_API_KEY  (required)
      POSTMAN_MCP_URL  (optional, defaults to https://mcp.postman.com/mcp)
    """

    US_DEFAULT = "https://mcp.postman.com/mcp"

    def __init__(self, base_url: str | None = None, api_key: str | None = None, timeout: int = 60):
        self.api_key = api_key or os.getenv("POSTMAN_API_KEY") or os.getenv("POSTMAN_API_TOKEN")
        if not self.api_key:
            raise RuntimeError("POSTMAN_API_KEY is required for Postman MCP calls.")

        env_url = (base_url or os.getenv("POSTMAN_MCP_URL") or self.US_DEFAULT).strip().rstrip("/")
        urls: List[str] = []
        for u in (env_url, self.US_DEFAULT):
            u = u.rstrip("/")
            if u not in urls:
                urls.append(u)
            if f"{u}/" not in urls:
                urls.append(f"{u}/")
        self.urls = urls
        self.timeout = timeout

    # ---------- internal permutations ----------

    def _header_permutations(self) -> List[Dict[str, str]]:
        """
        The server requires clients to accept BOTH application/json and text/event-stream.
        """
        common = {"User-Agent": "smart-api-security-agent/1.0"}
        accept_required = "application/json, text/event-stream"
        accept_plus_wild = f"{accept_required}, */*"

        return [
            # both auth hints; strict Accept (required)
            {
                **common,
                "Authorization": f"Bearer {self.api_key}",
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
                "Accept": accept_required,
            },
            # both auth; Accept with wildcard
            {
                **common,
                "Authorization": f"Bearer {self.api_key}",
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
                "Accept": accept_plus_wild,
            },
            # bearer only; strict Accept
            {
                **common,
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": accept_required,
            },
            # x-api-key only; strict Accept
            {
                **common,
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
                "Accept": accept_required,
            },
            # charset variant
            {
                **common,
                "Authorization": f"Bearer {self.api_key}",
                "X-API-Key": self.api_key,
                "Content-Type": "application/json; charset=utf-8",
                "Accept": accept_required,
            },
        ]

    # ---------- SSE helpers ----------

    @staticmethod
    def _parse_sse_to_json(text: str) -> Dict[str, Any]:
        """
        Parse Server-Sent Events payload (as a single accumulated string) into JSON.
        We concatenate all 'data: ' lines, then json.loads the join.
        """
        if not text:
            raise RuntimeError("Empty SSE response.")

        # Keep only 'data:' lines and strip the prefix
        datas: List[str] = []
        for line in text.splitlines():
            line = line.strip("\r\n")
            if line.startswith("data:"):
                datas.append(line[len("data:"):].strip())

        if not datas:
            # Heuristic: some gateways include leading "event:" then a single 'data: {...}'
            # If we didn't capture any, try to find the first '{'..'}' block.
            s = text
            try:
                start = s.find("{")
                end = s.rfind("}")
                if start != -1 and end != -1 and end > start:
                    return json.loads(s[start:end + 1])
            except Exception:
                pass
            raise RuntimeError(f"Unable to extract JSON from SSE:\n{text[:500]}")

        joined = "".join(datas).strip()
        # joined is expected to be a full JSON document
        return json.loads(joined)

    # ---------- core JSON-RPC with retries ----------

    def _rpc(self, url: str, headers: Dict[str, str], method: str, params: Dict[str, Any]):
        rid = str(uuid.uuid4())
        payload = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}

        r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=self.timeout)

        # Negotiation error is explicit from the gateway
        if r.status_code == 406:
            raise requests.HTTPError(
                f"406 Not Acceptable from {url} "
                f"(Accept={headers.get('Accept')!r}, Content-Type={headers.get('Content-Type')!r}). "
                f"Body: {r.text[:500]!r}",
                response=r,
            )

        r.raise_for_status()

        ctype = (r.headers.get("Content-Type") or "").lower()

        # Some deployments stream JSON-RPC results via SSE
        if "text/event-stream" in ctype or r.text.startswith("event:"):
            data = self._parse_sse_to_json(r.text)
        else:
            try:
                data = r.json()
            except Exception as e:
                raise RuntimeError(
                    f"Non-JSON response from {url} (status {r.status_code}): {r.text[:500]!r}"
                ) from e

        # JSON-RPC envelope check
        if isinstance(data, dict) and "error" in data and data["error"]:
            err = data["error"]
            raise RuntimeError(f"MCP error {err.get('code')}: {err.get('message')}")

        return data.get("result") if isinstance(data, dict) and "result" in data else data

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

    # ---------- public helpers (tools) ----------

    def call_tool(self, name: str, arguments: Dict[str, Any]):
        return self._rpc_with_fallbacks("tools/call", {"name": name, "arguments": arguments})

    def list_tools(self):
        return self._rpc_with_fallbacks("tools/list", {})

    # ---------- shape fixups ----------

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

    # ---------- convenience wrappers ----------

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
