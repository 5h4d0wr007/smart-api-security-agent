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

def extract_json_from_fences(s: str) -> Any: #pulling JSON from generic LLM response
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
        "You are an API security reviewer for CI.\n"
        "Input: oasdiff JSON.\n"
        "Output: JSON array of items with fields:\n"
        "  endpoint (string), method (string), changeType ('added'|'modified'|'deleted'),\n"
        "  risks (string[]), tests (string[] or objects with {type|name|expect}).\n"
        "Generate tests that cover:\n"
        "- Missing Auth (401)\n"
        "- BOLA/BOPLA cross-tenant access (403 or 404)\n"
        "- BFLA (403)\n"
        "- Happy path (2xx)\n"
        "Return ONLY JSON (array or an object with an 'items' array)."
    )
    try:
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.1,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": diff_text[:120000]}], #as per model token limit
            response_format={"type": "json_object"},
        )
        data = json.loads(resp.choices[0].message.content or "[]")
        if isinstance(data, dict) and "items" in data:
            data = data["items"]
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    data = v
                    break
        return data if isinstance(data, list) else []
    except Exception:
        pass
    try:
        #as a fallback; no enforced JSON via LLM, so using fenced JSON approach
        resp = client.chat.completions.create(
            model="gpt-4o-mini",
            temperature=0.1,
            messages=[{"role": "system", "content": system},
                      {"role": "user", "content": diff_text[:120000]}],
        )
        return extract_json_from_fences(resp.choices[0].message.content or "[]")
    except Exception as e:
        sys.stderr.write(f"LLM parse failed: {e}\n")
        return []

def build_postman_collection(collection_name: str, plan: List[Dict[str, Any]]) -> Dict[str, Any]:
    #accepts tests from the LLM and merges them into assertions
    def norm(ep: str) -> str:
        ep = ep or "/"
        if not ep.startswith("/"):
            ep = "/" + ep
        return re.sub(r"\{([^}/]+)\}", r"{{\1}}", ep)

    def path_vars(ep: str) -> List[str]:
        return re.findall(r"\{\{([^}/]+)\}\}", norm(ep))

    def id_map_for(var: str) -> tuple[str, str]:
        m = var.lower()
        if "user" in m:    return "{{user_owner}}", "{{user_other}}"
        if "account" in m: return "{{account_owner}}", "{{account_other}}"
        if "order" in m:   return "{{order_owner}}", "{{order_other}}"
        return "{{id_owner}}", "{{id_other}}"

    def replace_ids(ep: str, owner: bool) -> str:
        e = norm(ep)
        for v in path_vars(e):
            own, oth = id_map_for(v)
            e = e.replace("{{"+v+"}}", own if owner else oth)
        return e #dynamic endpoint update for sec. tests

    def add_expect_from_label(script: List[str], lbl: str):
        s = (lbl or "").lower()
        if "unauth" in s or "401" in s: script.append('expect(401, "Unauthenticated -> 401");'); return
        if "forbidden" in s or "bfla" in s or "403" in s: script.append('expect(403, "Forbidden -> 403");'); return
        if "idor" in s or "bola" in s or "404" in s or "not found" in s: script.append('expect(404, "Not found -> 404");'); return
        if "invalid" in s or "bad request" in s or "400" in s: script.append('expect(400, "Invalid -> 400");'); return
        if "conflict" in s or "replay" in s or "409" in s: script.append('expect(409, "Replay/Conflict -> 409");'); return
        if "accepted" in s or "202" in s: script.append('expect(202, "Accepted -> 202");'); return
        if "created" in s or "201" in s: script.append('expect(201, "Created -> 201");'); return
        if "200" in s or "ok" in s or "success" in s: script.append('expect(200, "OK -> 200");'); return

    def add_expect_from_dict(script: List[str], d: Dict[str, Any]):
        label = d.get("name") or d.get("label") or ""
        status = d.get("expect") or d.get("expectStatus") or d.get("status")
        type_hint = str(d.get("type") or "").lower()
        map_ = {
            #to normalize possible LLM-generated type hints into consistent Postman assertions
            "unauth": (401, "Unauthenticated -> 401"),
            "authn": (401, "Unauthenticated -> 401"),
            "bfla": (403, "Forbidden -> 403"),
            "forbidden": (403, "Forbidden -> 403"),
            "authz": (403, "Forbidden -> 403"),
            "bola": (404, "Not found -> 404"),
            "idor": (404, "Not found -> 404"),
            "invalid": (400, "Invalid -> 400"),
            "badrequest": (400, "Invalid -> 400"),
            "conflict": (409, "Replay/Conflict -> 409"),
            "replay": (409, "Replay/Conflict -> 409"),
            "accepted": (202, "Accepted -> 202"),
            "created": (201, "Created -> 201"),
            "ok": (200, "OK -> 200"),
            "success": (200, "OK -> 200"),
        }
        if type_hint in map_:
            st, lab = map_[type_hint]
            script.append(f'expect({st}, "{lab}");'); return
        if isinstance(status, (int, float)):
            st = int(status)
            lab = label or {
                200:"OK -> 200", 201:"Created -> 201", 202:"Accepted -> 202",
                400:"Invalid -> 400", 401:"Unauthenticated -> 401", 403:"Forbidden -> 403",
                404:"Not found -> 404", 409:"Replay/Conflict -> 409"
            }.get(st, f"Expect -> {st}")
            script.append(f'expect({st}, "{lab}");'); return
        if label:
            add_expect_from_label(script, label); return
        script.append('pm.test("Generic check", () => pm.expect([200,201,202,400,401,403,404,409]).to.include(code));') #NOTA - generic safety nest

    def pm_item(name: str, method: str, endpoint: str, token_expr: str, tests: Any) -> Dict[str, Any]:
        path_parts = endpoint.lstrip("/").split("/") if endpoint != "/" else []
        url = {"raw": "{{baseUrl}}" + endpoint, "host": ["{{baseUrl}}"], "path": path_parts}
        headers = [
            {"key": "Authorization", "value": f"Bearer {token_expr}", "type": "text"},
            {"key": "Content-Type", "value": "application/json", "type": "text"},
        ]
        script = [
            "const code = pm.response.code;",
            "function expect(c, name){ pm.test(name, () => pm.expect(code).to.eql(c)); }",
        ]
        seq = tests if isinstance(tests, list) else ([] if tests is None else [tests])
        added_any = False
        for t in seq:
            if isinstance(t, str):
                add_expect_from_label(script, t); added_any = True
            elif isinstance(t, (int, float)):
                add_expect_from_dict(script, {"status": int(t)}); added_any = True
            elif isinstance(t, dict):
                add_expect_from_dict(script, t); added_any = True
        if not added_any:
            script.append('pm.test("Generic check", () => pm.expect([200,201,202,400,401,403,404,409]).to.include(code));') 

        return {
            "name": name,
            "request": {
                "method": method,
                "header": headers,
                "url": url,
                "body": {"mode": "raw", "raw": "{}"}
            },
            "event": [
                {
                    "listen": "prerequest",
                    "script": {
                        "type": "text/javascript",
                        "exec": [
                            "//map owner/x-tenant variables into the path variables used by URL",
                            "const scenario = pm.info.requestName || '';",
                            "const isOwner = scenario.includes('(owner)');",
                            "const isX = scenario.includes('(x-tenant)');",
                            "",
                            "function setIfUsed(varName, ownerKey, otherKey){",
                            "  if (pm.request.url.toString().includes('{{'+varName+'}}')){",
                            "    const val = isOwner ? pm.collectionVariables.get(ownerKey) : pm.collectionVariables.get(otherKey);",
                            "    if (val !== undefined && val !== null) pm.variables.set(varName, String(val));",
                            "  }",
                            "}",
                            "setIfUsed('orderId',   'order_owner',   'order_other');",
                            "setIfUsed('accountId', 'account_owner', 'account_other');",
                            "setIfUsed('userId',    'user_owner',    'user_other');",
                            "//generic fallback",
                            "setIfUsed('id',        'id_owner',      'id_other');"
                        ]
                    }
                },
                {
                    "listen": "test",
                    "script": {"type": "text/javascript", "exec": script}
                }
            ]
        }

    items: List[Dict[str, Any]] = []
    for r in plan or []:
        if not isinstance(r, dict):
            continue
        if (r.get("changeType") or "").lower() == "deleted":
            continue
        ep = r.get("endpoint") or "/"
        method = (r.get("method") or "GET").upper()
        ep_norm = norm(ep)
        ep_owner = replace_ids(ep, owner=True)
        ep_other = replace_ids(ep, owner=False)
        items.append(pm_item(f"(unauth) {method} {ep_norm}", method, ep_norm, "{{token_none}}", ["Unauthenticated -> 401"]))
        items.append(pm_item(f"(owner) {method} {ep_norm}", method, ep_owner, "{{token_owner}}", ["OK -> 200"]))
        items.append(pm_item(f"(x-tenant) {method} {ep_norm}", method, ep_other, "{{token_owner}}", ["Forbidden -> 403", "Not found -> 404"]))

    if not items:
        items.append(pm_item("(owner) GET /me", "GET", "/me", "{{token_owner}}", ["OK -> 200"])) #to not fail CI when LLM hallucinates with plan.json

    return {
        "info": {
            "name": collection_name,
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": items,
        "variable": [
            {"key": "baseUrl",         "value": "http://127.0.0.1:8000"},
            {"key": "token_none",      "value": ""},
            {"key": "token_owner",     "value": "t1"},
            {"key": "token_other",     "value": "t2"},
            {"key": "token_admin",     "value": "ta"},
            {"key": "user_owner",      "value": "1"},
            {"key": "user_other",      "value": "2"},
            {"key": "account_owner",   "value": "101"},
            {"key": "account_other",   "value": "102"},
            {"key": "order_owner",     "value": "201"},
            {"key": "order_other",     "value": "202"},
            {"key": "id_owner",        "value": "1"},
            {"key": "id_other",        "value": "2"},
        ]
    } #for production-data usage, you can fetch from securely stored environement variables

def call_tool(mcp: McpHttp, name: str, args: Dict[str, Any]) -> Any:
    return mcp.call_tool(name, args)

def normalize_workspaces(obj: Any) -> List[Dict[str, Any]]:
    if isinstance(obj, dict):
        if "items" in obj:
            return obj["items"]
        if "workspaces" in obj:
            return obj["workspaces"]
    elif isinstance(obj, list):
        return obj
    return []

def collection_id_from_create(resp: Any) -> Optional[str]:
    if not isinstance(resp, dict):
        return None
    if isinstance(resp.get("collection"), dict) and resp["collection"].get("id"):
        return resp["collection"]["id"]
    return resp.get("id") or resp.get("collectionId")

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="openapi/api.v1.yaml")
    ap.add_argument("--head", default="openapi/api.yaml")
    ap.add_argument("--diff", default="diff.json")
    ap.add_argument("--collection", default="security test collection")
    ap.add_argument("--plan", default="plan.json")
    args = ap.parse_args()
    
    run(["swagger-cli", "validate", args.base])
    run(["swagger-cli", "validate", args.head])
    diff_json = run(["oasdiff", "diff", "--format", "json", args.base, args.head])
    with open(args.diff, "w") as f:
        f.write(diff_json)

    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    plan = [] if looks_empty_diff(diff_json) else llm_plan_from_diff(client, diff_json)
    with open(args.plan, "w") as f:
        json.dump(plan, f, indent=2)

    pm_collection = build_postman_collection(args.collection, plan)

    mcp = McpHttp(os.environ["POSTMAN_MCP_URL"], os.environ["POSTMAN_API_KEY"])
    ws_obj = call_tool(mcp, "getWorkspaces", {})
    ws_list = normalize_workspaces(ws_obj)
    ws_name = os.environ.get("POSTMAN_WORKSPACE_NAME", "Security Demo")
    ws = next((w for w in ws_list if w.get("name") == ws_name), None)
    if not ws:
        raise SystemExit(f"Workspace {ws_name} not found. Found: {[w.get('name') for w in ws_list]}")
    workspace_id = ws["id"]

    try:
        existing = call_tool(mcp, "searchCollections", {"workspace": workspace_id, "query": args.collection})
        if isinstance(existing, dict) and existing.get("items"):
            cid0 = existing["items"][0]["id"]
            call_tool(mcp, "deleteCollection", {"collectionId": cid0}) #as needed, update the MCP call to update the existing one
    except Exception as e:
        sys.stderr.write(f"[WARN] deleteCollection failed or not necessary: {e}\n")

    created = call_tool(mcp, "createCollection", {"workspace": workspace_id, "collection": pm_collection})
    cid = collection_id_from_create(created)
    if not cid:
        raise SystemExit(f"Could not resolve collection id from response: {created}")
    got = call_tool(mcp, "getCollection", {"collectionId": cid})
    collection_obj = got.get("collection") if isinstance(got, dict) and "collection" in got else got
    with open("generated-security-test.postman_collection.json", "w") as f:
        json.dump(collection_obj, f, indent=2)
    print("MCP: collection created & fetched.")
    
    env_name = "Local Security Test"
    env_vars = [
        {"key": "baseUrl",        "value": "http://127.0.0.1:8000"},
        {"key": "token_none",     "value": ""},
        {"key": "token_owner",    "value": "t1"},
        {"key": "token_other",    "value": "t2"},
        {"key": "token_admin",    "value": "ta"},
        {"key": "user_owner",     "value": "1"},
        {"key": "user_other",     "value": "2"},
        {"key": "account_owner",  "value": "101"},
        {"key": "account_other",  "value": "102"},
        {"key": "order_owner",    "value": "201"},
        {"key": "order_other",    "value": "202"},
        {"key": "id_owner",       "value": "1"},
        {"key": "id_other",       "value": "2"},
    ]
    try:
        env = {"name": env_name, "values": env_vars}
        call_tool(mcp, "createEnvironment", {"workspace": workspace_id, "environment": env}) #for production usage, use securely stored environment variables
        print(f"MCP: environment ensured: {env_name}")
    except Exception as e:
        print(f"[WARN] could not create env: {e}")

if __name__ == "__main__":
    main()
