#!/usr/bin/env python3
import os
import json
import uuid
import requests
from typing import Dict, Any, List


class PostmanMCP:
    """
    Resilient JSON-RPC client for the Postman MCP full server (US region only).

    Features:
      - Uses US URL only (https://mcp.postman.com/mcp) unless overridden by POSTMAN_MCP_URL.
      - Sets Accept: application/json, text/event-stream (required by MCP).
      - Detects and parses SSE (Server-Sent Events) responses.
      - Tries with/without trailing slash and multiple auth header variants.
      - Surfaces meaningful body text on errors.

    Env:
      POSTMAN_API_KEY  (required)
      POSTMAN_MCP_URL  (optional)
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

    # ---------- header permutations ----------
    def _header_permutations(self) -> List[Dict[str, str]]:
        """Server requires Accept: application/json, text/event-stream."""
        common = {"User-Agent": "smart-api-security-agent/1.0"}
        accept_required = "application/json, text/event-stream"
        return [
            {
                **common,
                "Authorization": f"Bearer {self.api_key}",
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
                "Accept": accept_required,
            },
            {
                **common,
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
                "Accept": accept_required,
            },
            {
                **common,
                "X-API-Key": self.api_key,
                "Content-Type": "application/json",
                "Accept": accept_required,
            },
            {
                **common,
                "Authorization": f"Bearer {self.api_key}",
                "X-API-Key": self.api_key,
                "Content-Type": "application/json; charset=utf-8",
                "Accept": accept_required,
            },
        ]

    # ---------- SSE parsing ----------
    @staticmethod
    def _parse_sse_to_json(text: str) -> Dict[str, Any]:
        """Extract JSON from text/event-stream payloads."""
        if not text:
            raise RuntimeError("Empty SSE response.")

        data_lines: List[str] = [ln[len("data:"):].strip() for ln in text.splitlines() if ln.startswith("data:")]
        if not data_lines:
            # fallback: find JSON braces
            try:
                start, end = text.find("{"), text.rfind("}")
                if start != -1 and end != -1 and end > start:
                    return json.loads(text[start:end + 1])
            except Exception:
                pass
            raise RuntimeError(f"Unable to parse SSE content: {text[:400]}")
        joined = "".join(data_lines).strip()
        return json.loads(joined)

    # ---------- core JSON-RPC ----------
    def _rpc(self, url: str, headers: Dict[str, str], method: str, params: Dict[str, Any]):
        rid = str(uuid.uuid4())
        payload = {"jsonrpc": "2.0", "id": rid, "method": method, "params": params}
        r = requests.post(url, headers=headers, data=json.dumps(payload), timeout=self.timeout)
        r.raise_for_status()

        ctype = (r.headers.get("Content-Type") or "").lower()
        if "text/event-stream" in ctype or r.text.startswith("event:"):
            data = self._parse_sse_to_json(r.text)
        else:
            try:
                data = r.json()
            except Exception as e:
                raise RuntimeError(
                    f"Non-JSON response from {url} (status {r.status_code}): {r.text[:400]!r}"
                ) from e

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
        raise last_err or RuntimeError("MCP call failed after all retries")

    # ---------- high-level tools ----------
    def call_tool(self, name: str, arguments: Dict[str, Any]):
        return self._rpc_with_fallbacks("tools/call", {"name": name, "arguments": arguments})

    def list_tools(self):
        return self._rpc_with_fallbacks("tools/list", {})

    # ---------- shape normalization ----------
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

    # ---------- convenience wrappers ----------
    def get_workspaces(self):
        return self._coerce_text_json(self.call_tool("getWorkspaces", {}))

    def get_collections(self, workspace_id: str):
        return self._coerce_text_json(self.call_tool("getCollections", {"workspace": workspace_id}))

    def get_collection(self, collection_id: str):
        return self._coerce_text_json(self.call_tool("getCollection", {"collectionId": collection_id}))

    def create_collection(self, workspace_id: str, collection_obj: dict):
        return self._coerce_text_json(
            self.call_tool("createCollection", {"workspace": workspace_id, "collection": collection_obj})
        )

    def update_collection(self, collection_id: str, collection_obj: dict):
        return self._coerce_text_json(
            self.call_tool("updateCollection", {"collectionId": collection_id, "collection": collection_obj})
        )

    def get_environments(self, workspace_id: str):
        return self._coerce_text_json(self.call_tool("getEnvironments", {"workspace": workspace_id}))

    def create_environment(self, workspace_id: str, name: str, variables: dict):
        return self._coerce_text_json(
            self.call_tool(
                "createEnvironment",
                {
                    "workspace": workspace_id,
                    "environment": {
                        "name": name,
                        "values": [{"key": k, "value": v} for k, v in variables.items()],
                    },
                },
            )
        )

    def update_environment(self, environment_id: str, name: str, variables: dict):
        return self._coerce_text_json(
            self.call_tool(
                "updateEnvironment",
                {
                    "environmentId": environment_id,
                    "environment": {
                        "name": name,
                        "values": [{"key": k, "value": v} for k, v in variables.items()],
                    },
                },
            )
        )

    def upsert_environment(self, workspace_id: str, name: str, variables: dict):
        try:
            return self.create_environment(workspace_id, name, variables)
        except Exception:
            envs = self.get_environments(workspace_id) or {}
            env = next((e for e in (envs.get("environments") or []) if e.get("name") == name), None)
            if not env:
                raise
            return self.update_environment(env["id"], name, variables)
