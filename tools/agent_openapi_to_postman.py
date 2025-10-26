# tools/agent_openapi_to_postman.py
import os, json, sys, subprocess, argparse, re, time
from typing import Any, Dict, List, Optional, Tuple
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
        url = {"raw": "{{baseUrl}}"+endpoint, "host": ["{{baseUrl}}"], "path": endpoint.lstrip("/").split("/")}
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
            if "unauth" in s:                       script.append('expect(401, "Unauthenticated -> 401");')
            elif "forbidden" in s or "role" in s:    script.append('expect(403, "Forbidden -> 403");')
            elif "invalid" in s or "bad request" in s: script.append('expect(400, "Invalid -> 400");')
            elif "replay" in s or "conflict" in s:   script.append('expect(409, "Replay/Conflict -> 409");')
            elif "not found" in s:                   script.append('expect(404, "Not found -> 404");')
            elif "202" in s:                         script.append('expect(202, "Accepted -> 202");')
            elif "201" in s:                         script.append('expect(201, "Created -> 201");')
            elif "200" in s or "ok" in s:            script.append('expect(200, "OK -> 200");')
            else:                                    script.append('pm.test("Generic check", () => pm.expect([200,201,202,400,401,403,404,409]).to.include(code));')
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
        "info": {"name": collection_name, "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": items,
        "variable": [
            {"key":"baseUrl","value":"http://127.0.0.1:8000"},
            {"key":"token","value":"demo-token"}
        ]
    }

# ---------- MCP helpers (tool aliasing & shape normalization) ----------

def call_tool_with_aliases(mcp: McpHttp, names: List[str], args: Dict[str, Any]) -> Any:
    """
    Try a list of tool names until one succeeds (handles v2 camelCase and v1 snake_case).
    Treat 'Tool ... not found' or JSON-RPC -32601 as a miss and continue.
    """
    last_err = None
    for name in names:
        try:
            res = mcp.call_tool(name, args)
            # Some servers return {'error': {...}} in-band; treat as exception-like
            if isinstance(res, dict) and "error" in res:
                last_err = RuntimeError(str(res["error"]))
                continue
            return res
        except Exception as e:
            msg = str(e)
            if "not found" in msg.lower() or "-32601" in msg:
                last_err = e
                continue
            # For invalid args (-32602), let caller decide; bubble up
            last_err = e
            break
    if last_err:
        raise last_err
    return None

def normalize_workspaces(obj: Any) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    if isinstance(obj, dict):
        if isinstance(obj.get("items"), list):
            items = obj["items"]
        elif isinstance(obj.get("workspaces"), list):
            items = obj["workspaces"]
        elif isinstance(obj.get("content"), list):
            texts = [c.get("text","") for c in obj["content"] if isinstance(c, dict)]
            joined = "\n".join(texts)
            try:
                parsed = json.loads(joined)
                if isinstance(parsed, dict):
                    if isinstance(parsed.get("items"), list): items = parsed["items"]
                    elif isinstance(parsed.get("workspaces"), list): items = parsed["workspaces"]
            except Exception:
                pass
        elif obj.get("id") and obj.get("name"):
            items = [obj]
    elif isinstance(obj, list):
        items = [w for w in obj if isinstance(w, dict)]
    return items

def collection_id_from_create(resp: Any) -> Optional[str]:
    if not isinstance(resp, dict):
        return None
    if isinstance(resp.get("collection"), dict) and resp["collection"].get("id"):
        return resp["collection"]["id"]
    if resp.get("id"):
        return resp["id"]
    if resp.get("collectionId"):
        return resp["collectionId"]
    return None

def find_collection_id(mcp: McpHttp, workspace_id: str, name: str) -> Optional[str]:
    # Try search (v2 full), then list (snake_case), then list (camelCase)
    # 1) searchCollections (preferred when available)
    try:
        res = call_tool_with_aliases(mcp, ["searchCollections"], {"workspaceId": workspace_id, "query": name})
        if isinstance(res, dict) and isinstance(res.get("items"), list):
            for it in res["items"]:
                if isinstance(it, dict) and it.get("name") == name:
                    return it.get("id")
    except Exception:
        pass
    # 2) list_collections (v1/v2-snake)
    try:
        res = call_tool_with_aliases(mcp, ["list_collections"], {"workspaceId": workspace_id})
        lst = []
        if isinstance(res, dict) and isinstance(res.get("items"), list): lst = res["items"]
        elif isinstance(res, list): lst = res
        for it in lst:
            if isinstance(it, dict) and it.get("name") == name:
                return it.get("id")
    except Exception:
        pass
    # 3) listCollections (camelCase variant)
    try:
        res = call_tool_with_aliases(mcp, ["listCollections"], {"workspaceId": workspace_id})
        if isinstance(res, dict) and isinstance(res.get("items"), list):
            for it in res["items"]:
                if isinstance(it, dict) and it.get("name") == name:
                    return it.get("id")
    except Exception:
        pass
    return None

# ----------------------------------------------------------------------

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

    # 2) LLM → plan
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
    workspaces_obj = call_tool_with_aliases(mcp, ["getWorkspaces", "get_workspaces"], {})
    if workspaces_obj is None:
        raise SystemExit("MCP getWorkspaces returned no content. Check POSTMAN_MCP_URL, API key, and network.")
    ws_items = normalize_workspaces(workspaces_obj)
    if not ws_items:
        raise SystemExit(f"Unexpected getWorkspaces shape: {type(workspaces_obj)} {str(workspaces_obj)[:300]}")
    ws_name = os.environ.get("POSTMAN_WORKSPACE_NAME","Security Demo")
    ws = next((w for w in ws_items if w.get("name")==ws_name), None)
    if not ws:
        names = [w.get("name") for w in ws_items if isinstance(w, dict)]
        raise SystemExit(f"Workspace not found by name: {ws_name} (found: {names})")
    workspace_id = ws["id"]

    # 5) Idempotency: delete existing collection with same name (best-effort)
    try:
        existing = call_tool_with_aliases(mcp, ["searchCollections"], {"workspaceId": workspace_id, "query": args.collection})
        if isinstance(existing, dict) and isinstance(existing.get("items"), list) and existing["items"]:
            cid0 = existing["items"][0].get("id")
            if cid0:
                try:
                    call_tool_with_aliases(mcp, ["deleteCollection", "delete_collection"], {"id": cid0})
                except Exception as e:
                    sys.stderr.write(f"[WARN] deleteCollection failed (continuing): {e}\n")
    except Exception:
        pass

    # 6) Create collection WITH full object (works on v2 camelCase and v1 snake_case)
    try:
        created = call_tool_with_aliases(mcp, ["createCollection"], {"workspaceId": workspace_id, "collection": pm_collection})
    except Exception:
        created = call_tool_with_aliases(mcp, ["create_collection"], {"workspaceId": workspace_id, "collection": pm_collection})

    cid = collection_id_from_create(created)
    if not cid:
        cid = find_collection_id(mcp, workspace_id, args.collection)
    if not cid:
        raise SystemExit(f"Could not resolve created collection id. Response: {str(created)[:300]}")

    # 7) Fetch (export) collection using get tool (there is NO exportCollection tool)
    # Try camelCase first, then snake_case
    try:
        got = call_tool_with_aliases(mcp, ["getCollection"], {"id": cid, "format": "v2.1"})
    except Exception:
        got = call_tool_with_aliases(mcp, ["get_collection"], {"id": cid})  # some servers ignore 'format'

    # Normalize shapes:
    # - {"collection": {...}}
    # - full collection object directly
    # - message envelope already unwrapped by client
    collection_obj = None
    if isinstance(got, dict) and "collection" in got and isinstance(got["collection"], dict):
        collection_obj = got["collection"]
    elif isinstance(got, dict) and got.get("info") and got.get("item"):
        collection_obj = got
    else:
        # As a last resort, try list and pick by id
        fallback = find_collection_id(mcp, workspace_id, args.collection)
        if fallback == cid:
            # Try another get without format hint
            got2 = call_tool_with_aliases(mcp, ["getCollection", "get_collection"], {"id": cid})
            if isinstance(got2, dict) and "collection" in got2 and isinstance(got2["collection"], dict):
                collection_obj = got2["collection"]
            elif isinstance(got2, dict) and got2.get("info") and got2.get("item"):
                collection_obj = got2

    if not collection_obj:
        raise SystemExit(f"Unexpected getCollection response: {type(got)} {str(got)[:300]}")

    with open("generated-security-test.postman_collection.json","w") as f:
        json.dump(collection_obj, f, indent=2)

    print("MCP: collection created & fetched.")

if __name__ == "__main__":
    main()
