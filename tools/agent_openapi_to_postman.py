# tools/agent_openapi_to_postman.py
import os, json, sys, subprocess, argparse, re, time
from typing import Any, Dict, List, Optional
from mcp_client import McpHttp
from openai import OpenAI

def run(cmd: list[str]) -> str:
    print("+", " ".join(cmd), flush=True)
    cp = subprocess.run(cmd, capture_output=True, text=True)
    if cp.returncode != 0:
        sys.stderr.write(cp.stdout + "\n" + cp.stderr + "\n")
        raise SystemExit(cp.returncode)
    return cp.stdout

def looks_empty_diff(diff_text: str) -> bool:
    try:
        d = json.loads(diff_text or "{}")
        return d == {} or all(not d.get(k) for k in d.keys())
    except Exception:
        return False

def parse_json_strict(s: str) -> Any:
    return json.loads(s)

def extract_json_from_fences(s: str) -> Any:
    m = re.search(r"```json\s*([\s\S]*?)```", s, re.IGNORECASE)
    if m:
        return json.loads(m.group(1))
    m = re.search(r"(\{[\s\S]*\})", s)
    if m:
        return json.loads(m.group(1))
    m = re.search(r"(\[[\s\S]*\])", s)
    if m:
        return json.loads(m.group(1))
    raise ValueError("No JSON found in content")

def llm_plan_from_diff(client: OpenAI, diff_text: str) -> List[Dict[str, Any]]:
    system = (
        "You are an API security reviewer for CI. "
        "Input: oasdiff JSON. "
        "Output: a JSON array of items with fields: "
        "{endpoint, method, changeType: 'added'|'modified'|'deleted', risks: string[], tests: string[]}. "
        "Focus on authn/authz, IDOR, input validation, idempotency (409), rate limiting, and 2xx happy-paths. "
        "Return ONLY JSON."
    )

    tries = 0
    last_err = None
    while tries < 3:
        tries += 1
        try:
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                temperature=0.1,
                messages=[{"role":"system","content":system},
                          {"role":"user","content":diff_text[:120000]}],
                response_format={"type": "json_object"},
            )
            content = resp.choices[0].message.content or ""
            data = parse_json_strict(content)
            if isinstance(data, dict) and "items" in data:
                data = data["items"]
            if isinstance(data, dict):
                for _, v in data.items():
                    if isinstance(v, list):
                        data = v
                        break
            if not isinstance(data, list):
                raise ValueError("Model did not return a JSON array")
            return data
        except Exception as e:
            last_err = e
            try:
                resp = client.chat.completions.create(
                    model="gpt-4o-mini",
                    temperature=0.1,
                    messages=[{"role":"system","content":system},
                              {"role":"user","content":diff_text[:120000]}],
                )
                content = resp.choices[0].message.content or ""
                data = extract_json_from_fences(content)
                if not isinstance(data, list):
                    raise ValueError("Extracted JSON is not a list")
                return data
            except Exception as e2:
                last_err = e2
                time.sleep(1.0)
    sys.stderr.write(f"[WARN] LLM JSON parsing failed after retries: {last_err}\n")
    return []

def build_postman_collection(collection_name: str, plan: List[Dict[str,Any]]) -> Dict[str,Any]:
    def pm_item(endpoint: str, method: str, tests: List[str]) -> Dict[str,Any]:
        url = {
            "raw": "{{baseUrl}}"+endpoint,
            "host": ["{{baseUrl}}"],
            "path": endpoint.lstrip("/").split("/")
        }
        headers = [
            {"key":"Authorization","value":"Bearer {{token}}","type":"text"},
            {"key":"Content-Type","value":"application/json","type":"text"},
        ]
        script = [
            "const code = pm.response.code;",
            "function expect(c, name){ pm.test(name, () => pm.expect(code).to.eql(c)); }",
        ]
        for t in tests or []:
            s = t.lower()
            if "unauth" in s:                 script.append('expect(401, "Unauthenticated -> 401");')
            elif "forbidden" in s or "role" in s: script.append('expect(403, "Forbidden -> 403");')
            elif "invalid" in s or "bad request" in s: script.append('expect(400, "Invalid -> 400");')
            elif "replay" in s or "conflict" in s:     script.append('expect(409, "Replay/Conflict -> 409");')
            elif "not found" in s:             script.append('expect(404, "Not found -> 404");')
            elif "202" in s:                   script.append('expect(202, "Accepted -> 202");')
            elif "201" in s:                   script.append('expect(201, "Created -> 201");')
            elif "200" in s or "ok" in s:      script.append('expect(200, "OK -> 200");')
            else:                               script.append('pm.test("Generic check", () => pm.expect([200,201,202,400,401,403,404,409]).to.include(code));')
        return {
            "name": f"{method} {endpoint}",
            "request": {"method": method, "header": headers, "url": url, "body": {"mode":"raw","raw":"{}"}},
            "event": [{"listen":"test","script":{"type":"text/javascript","exec":script}}]
        }

    items: List[Dict[str,Any]] = []
    for r in plan:
        if r.get("changeType") == "deleted":
            continue
        endpoint = r.get("endpoint") or "/"
        method = (r.get("method") or "GET").upper()
        items.append(pm_item(endpoint, method, r.get("tests") or []))

    if not items:
        items.append(pm_item("/", "GET", ["OK -> 200"]))

    return {
        "info": {
            "name": collection_name,
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": items,
        "variable": [
            {"key":"baseUrl","value":"http://127.0.0.1:8000"},
            {"key":"token","value":"demo-token"}
        ]
    }

def _normalize_workspace_list(workspaces_obj: Any) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    if isinstance(workspaces_obj, dict):
        if isinstance(workspaces_obj.get("items"), list):
            items = workspaces_obj["items"]
        elif isinstance(workspaces_obj.get("workspaces"), list):
            items = workspaces_obj["workspaces"]
        elif isinstance(workspaces_obj.get("content"), list):
            texts = [c.get("text","") for c in workspaces_obj["content"] if isinstance(c, dict)]
            joined = "\n".join(texts)
            try:
                parsed = json.loads(joined)
                if isinstance(parsed, dict):
                    if isinstance(parsed.get("items"), list):
                        items = parsed["items"]
                    elif isinstance(parsed.get("workspaces"), list):
                        items = parsed["workspaces"]
            except Exception:
                pass
        else:
            if workspaces_obj.get("id") and workspaces_obj.get("name"):
                items = [workspaces_obj]
    elif isinstance(workspaces_obj, list):
        items = [w for w in workspaces_obj if isinstance(w, dict)]
    return items

def _extract_collection_id_from_create(resp: Any) -> Optional[str]:
    # Handle multiple shapes:
    # - {"collection":{"id":"...","uid":"..."}}
    # - {"id":"..."} or {"collectionId":"..."}
    # - Message envelope already unwrapped by client; still be defensive.
    if not isinstance(resp, dict):
        return None
    if isinstance(resp.get("collection"), dict) and resp["collection"].get("id"):
        return resp["collection"]["id"]
    if resp.get("id"):
        return resp["id"]
    if resp.get("collectionId"):
        return resp["collectionId"]
    return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="openapi/api.v1.yaml")
    ap.add_argument("--head", default="openapi/api.yaml")
    ap.add_argument("--diff", default="diff.json")
    ap.add_argument("--collection", default="security test collection")
    ap.add_argument("--plan", default="plan.json")
    args = ap.parse_args()

    # 1) Validate & diff
    run(["swagger-cli", "validate", args.base])
    run(["swagger-cli", "validate", args.head])
    diff_json = run(["oasdiff", "diff", "--format", "json", args.base, args.head])
    with open(args.diff, "w") as f: f.write(diff_json)

    # 2) LLM → plan (robust)
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    if looks_empty_diff(diff_json):
        plan: List[Dict[str, Any]] = []
    else:
        plan = llm_plan_from_diff(client, diff_json)
    with open(args.plan, "w") as f: json.dump(plan, f, indent=2)

    # 3) Build collection JSON (v2.1)
    pm_collection = build_postman_collection(args.collection, plan)

    # 4) Postman MCP: find workspace
    mcp = McpHttp(os.environ["POSTMAN_MCP_URL"], os.environ["POSTMAN_API_KEY"])
    workspaces_obj = mcp.call_tool("getWorkspaces", {})
    if workspaces_obj is None:
        raise SystemExit("MCP getWorkspaces returned no content. Check POSTMAN_MCP_URL, API key, and network.")
    items = _normalize_workspace_list(workspaces_obj)
    if not items:
        raise SystemExit(f"Unexpected getWorkspaces shape: {type(workspaces_obj)} {str(workspaces_obj)[:300]}")
    ws_name = os.environ.get("POSTMAN_WORKSPACE_NAME","Security Demo")
    ws = next((w for w in items if w.get("name")==ws_name), None)
    if not ws:
        names = [w.get("name") for w in items if isinstance(w, dict)]
        raise SystemExit(f"Workspace not found by name: {ws_name} (found: {names})")
    workspace_id = ws["id"]

    # 5) Ensure idempotency: delete any existing collection with same name
    existing = mcp.call_tool("searchCollections", {"workspaceId": workspace_id, "query": args.collection})
    if isinstance(existing, dict) and isinstance(existing.get("items"), list) and existing["items"]:
        try:
            mcp.call_tool("deleteCollection", {"id": existing["items"][0]["id"]})
        except Exception as e:
            sys.stderr.write(f"[WARN] deleteCollection failed (continuing): {e}\n")

    # 6) ✅ Create collection by passing the FULL collection object (not just name)
    created = mcp.call_tool("createCollection", {
        "workspaceId": workspace_id,
        "collection": pm_collection
    })
    cid = _extract_collection_id_from_create(created)

    # Fallback: if we didn't get an id back, search by name
    if not cid:
        post_create_search = mcp.call_tool("searchCollections", {"workspaceId": workspace_id, "query": args.collection})
        if isinstance(post_create_search, dict) and isinstance(post_create_search.get("items"), list) and post_create_search["items"]:
            cid = post_create_search["items"][0].get("id")
    if not cid:
        raise SystemExit(f"Could not resolve created collection id. Response: {str(created)[:300]}")

    # 7) Export collection
    exported = mcp.call_tool("exportCollection", {"id": cid, "format": "v2.1"})
    if not (isinstance(exported, dict) and "collection" in exported):
        raise SystemExit(f"Unexpected exportCollection response: {type(exported)} {str(exported)[:200]}")

    with open("generated-security-test.postman_collection.json","w") as f:
        json.dump(exported["collection"], f, indent=2)

    print("MCP: collection created & exported.")

if __name__ == "__main__":
    main()
