import json
import uuid
import requests
from typing import Any, Dict, Optional, List

def _maybe_parse_json_string(s: str) -> Any:
    s = (s or "").strip()
    if not s:
        return None
    try:
        return json.loads(s)
    except Exception:
        pass
    for opener, closer in (("{", "}"), ("[", "]")):
        start = s.find(opener)
        end = s.rfind(closer)
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(s[start:end+1])
            except Exception:
                continue
    return None

class McpHttp:
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

        if r.status_code in (202, 204):
            return None
        r.raise_for_status()

        body = r.text or ""
        if not body.strip():
            return None

        ctype = (r.headers.get("Content-Type") or "").lower()

        if "application/json" in ctype:
            try:
                data = r.json()
            except requests.exceptions.JSONDecodeError:
                data = _maybe_parse_json_string(body)

            if isinstance(data, dict) and "result" in data:
                res = data["result"]
                if isinstance(res, dict) and "content" in res:
                    unwrapped = self._unwrap_content(res["content"])
                    return unwrapped if unwrapped is not None else res
                return res
                
            if isinstance(data, dict) and "content" in data:
                unwrapped = self._unwrap_content(data["content"])
                return unwrapped if unwrapped is not None else data

            return data

        if "text/event-stream" in ctype or body.startswith("event:") or "data:" in body:
            last_json = None
            for raw_line in body.splitlines():
                line = raw_line.strip()
                if not line.startswith("data:"):
                    continue
                js = _maybe_parse_json_string(line[5:].lstrip())
                if js is not None:
                    if isinstance(js, dict) and "result" in js:
                        last_json = js["result"]
                    else:
                        last_json = js
            if isinstance(last_json, dict) and "content" in last_json:
                unwrapped = self._unwrap_content(last_json["content"])
                return unwrapped if unwrapped is not None else last_json
            return last_json

        parsed = _maybe_parse_json_string(body)
        return parsed if parsed is not None else body

    def _unwrap_content(self, content: Any) -> Any:
        if not isinstance(content, list):
            return None
        texts: List[str] = []
        for part in content:
            if isinstance(part, dict) and part.get("type") == "text":
                t = part.get("text", "")
                if t:
                    texts.append(str(t))
        joined = "\n".join(texts)
        parsed = _maybe_parse_json_string(joined)
        return parsed

    def list_tools(self) -> Any:
        return self._rpc("tools/list", {})

    def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        return self._rpc("tools/call", {"name": name, "arguments": arguments})
