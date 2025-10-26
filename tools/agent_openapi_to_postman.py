# tools/agent_openapi_to_postman.py
import os, json, sys, subprocess, argparse, re, time
from typing import Any, Dict, List, Optional
from mcp_client import McpHttp
from openai import OpenAI

# ----------------- small shell helper -----------------
def run(cmd: list[str]) -> str:
    print("+", " ".join(cmd), flush=True)
    cp = subprocess.run(cmd, capture_output=True, text=True)
    if cp.returncode != 0:
        sys.stderr.write(cp.stdout + "\n" + cp.stderr + "\n")
        raise SystemExit(cp.returncode)
    return cp.stdout

# ----------------- diff helpers -----------------
def looks_empty_diff(diff_text: str) -> bool:
    try:
        d = json.loads(diff_text or "{}")
        return d == {} or all(not d.get(k) for k in d.keys())
    except Exception:
        return False

# ----------------- LLM helpers -----------------
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
        "Output: JSON array {endpoint, method, changeType, risks[], tests[]}. "
        "Generate tests simulating OWASP API Top10: "
        " - Missing Auth (expect 401)"
        " - BOLA: access other user's resource (expect 403)"
        " - BFLA: normal user performing admin-only (expect 403)"
        " - Valid authorized success (expect 2xx)"
        "Return ONLY JSON."
    )
    tries = 0
    while tries < 3:
        tries += 1
        try:
            resp = client.chat.completions.create(
                model="gpt-4o-mini",
                temperature=0.1,
                messages=[{"role": "system", "content": system},
                          {"role": "user", "content": diff_text[:120000]}],
                response_format={"type": "json_object"},
            )
            data = json.loads(resp.choices[0].message.content)
            if isinstance(data, dict) and "items" in data:
                data = data["items"]
            if isinstance(data, dict):
                for _, v in data.items():
                    if isinstance(v, list):
                        data = v
                        break
            return data if isinstance(data, list) else []
        except Exception as e:
            sys.stderr.write(f"[WARN] LLM parse failed ({e}), retrying...\n")
            time.sleep(1)
    return []

# ----------------- Postman collection builder (robust tests) -----------------
def build_postman_collection(collection_name: str, plan: List[Dict[str,Any]]) -> Dict[str,Any]:
    def normalize_endpoint(ep: str) -> str:
        ep = ep or "/"
        if not ep.startswith("/"):
            ep = "/" + ep
        # Turn /pets/{id}/transfer -> /pets/{{id}}/transfer
        return re.sub(r"\{([^}/]+)\}", r"{{\1}}", ep)

    def add_expect_from_keywords(script: List[str], s: str) -> bool:
        s_l = s.lower()
        if "unauth" in s_l or "401" in s_l:
            script.append('expect(401, "Unauthenticated -> 401");'); return True
        if "forbidden" in s_l or "role" in s_l or "403" in s_l or "bfla" in s_l:
            script.append('expect(403, "Forbidden -> 403");'); return True
        if "idor" in s_l or "bola" in s_l or "404" in s_l or "not found" in s_l:
            script.append('expect(404, "Not found -> 404");'); return True
        if "invalid" in s_l or "bad request" in s_l or "400" in s_l:
            script.append('expect(400, "Invalid -> 400");'); return True
        if "conflict" in s_l or "replay" in s_l or "409" in s_l:
            script.append('expect(409, "Replay/Conflict -> 409");'); return True
        if "accepted" in s_l or "202" in s_l:
            script.append('expect(202, "Accepted -> 202");'); return True
        if "created" in s_l or "201" in s_l:
            script.append('expect(201, "Created -> 201");'); return True
        if "ok" in s_l or "success" in s_l or "200" in s_l:
            script.append('expect(200, "OK -> 200");'); return True
        return False

    def add_expect_from_dict(script: List[str], d: Dict[str, Any]):
        # Supported shapes:
        # {"name":"Unauthenticated -> 401","expect":401}
        # {"label":"Forbidden -> 403","expectStatus":403}
        # {"status":404}
        # {"type":"unauth"|"bfla"|"bola"|"ok"|"created"|"accepted"|"invalid"|"conflict"}
        label = d.get("name") or d.get("label") or ""
        status = d.get("expect") or d.get("expectStatus") or d.get("status")

        type_hint = str(d.get("type") or "").lower()
        type_map = {
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
        if type_hint in type_map:
            st, lab = type_map[type_hint]
            script.append(f'expect({st}, "{lab}");')
            return

        if isinstance(status, (int, float)) and int(status) in {200,201,202,400,401,403,404,409}:
            st = int(status)
            lab = label or {
                200:"OK -> 200", 201:"Created -> 201", 202:"Accepted -> 202",
                400:"Invalid -> 400", 401:"Unauthenticated -> 401", 403:"Forbidden -> 403",
                404:"Not found -> 404", 409:"Replay/Conflict -> 409"
            }.get(st, f"Expect -> {st}")
            script.append(f'expect({st}, "{lab}");')
            return

        if label and add_expect_from_keywords(script, label):
            return

        script.append('pm.test("Generic check", () => pm.expect([200,201,202,400,401,403,404,409]).to.include(code));')

    def pm_item(endpoint: str, method: str, tests: Any) -> Dict[str,Any]:
        endpoint = normalize_endpoint(endpoint or "/")
        path_parts = endpoint.lstrip("/").split("/") if endpoint != "/" else []
        url = {"raw": "{{baseUrl}}" + endpoint, "host": ["{{baseUrl}}"], "path": path_parts}
        headers = [
            {"key":"Authorization","value":"Bearer {{token}}","type":"text"},
            {"key":"Content-Type","value":"application/json","type":"text"},
        ]
        script = [
            "const code = pm.response.code;",
            "function expect(c, name){ pm.test(name, () => pm.expect(code).to.eql(c)); }",
        ]

        seq = tests if isinstance(tests, list) else ([] if tests is None else [tests])
        added_any = False
        for t in seq:
            if isinstance(t, str):
                if add_expect_from_keywords(script, t):
                    added_any = True
                else:
                    m = re.search(r"\b(200|201|202|400|401|403|404|409)\b", t)
                    if m:
                        add_expect_from_dict(script, {"status": int(m.group(1)), "label": t})
                        added_any = True
            elif isinstance(t, (int, float)):
                add_expect_from_dict(script, {"status": int(t)})
                added_any = True
            elif isinstance(t, dict):
                add_expect_from_dict(script, t)
                added_any = True

        if not added_any:
            script.append('pm.test("Generic check", () => pm.expect([200,201,202,400,401,403,404,409]).to.include(code));')

        return {
            "name": f"{method} {endpoint}",
            "request": {"method": method, "header": headers, "url": url, "body": {"mode":"raw","raw":"{}"}},
            "event": [{"listen":"test","script":{"type":"text/javascript","exec":script}}]
        }

    # Build items from plan (tolerant to odd shapes)
    items: List[Dict[str,Any]] = []
    for r in plan or []:
        if not isinstance(r, dict):
            continue
        if (r.get("changeType") or "").lower() == "deleted":
            continue
        endpoint = r.get("endpoint") or "/"
        method = (r.get("method") or "GET").upper()
        items.append(pm_item(endpoint, method, r.get("tests")))

    if not items:
        items.append(pm_item("/", "GET", ["OK -> 200"]))

    return {
        "info": {"name": collection_name, "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": items,
        "variable": [
            {"key":"baseUrl","value":"http://127.0.0.1:8000"},
            {"key":"token","value":"token-user-u1"},
            {"key":"id","value":"p1"}
        ]
    }

# ---------- MCP helpers ----------
def call_tool(mcp: McpHttp, name: str, args: Dict[str, Any]) -> Any:
    return mcp.call_tool(name, args)

def normalize_workspaces(obj: Any) -> List[Dict[str, Any]]:
    if isinstance(obj, dict):
        if "items" in obj: return obj["items"]
        if "workspaces" in obj: return obj["workspaces"]
    elif isinstance(obj, list):
        return obj
    return []

def collection_id_from_create(resp: Any) -> Optional[str]:
    if not isinstance(resp, dict): return None
    if isinstance(resp.get("collection"), dict) and resp["collection"].get("id"):
        return resp["collection"]["id"]
    return resp.get("id") or resp.get("collectionId")

# ----------------- main -----------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="openapi/api.v1.yaml")
    ap.add_argument("--head", default="openapi/api.yaml")
    ap.add_argument("--diff", default="diff.json")
    ap.add_argument("--collection", default="security test collection")
    ap.add_argument("--plan", default="plan.json")
    args = ap.parse_args()

    # Validate & diff
    run(["swagger-cli", "validate", args.base])
    run(["swagger-cli", "validate", args.head])
    diff_json = run(["oasdiff", "diff", "--format", "json", args.base, args.head])
    with open(args.diff, "w") as f: f.write(diff_json)

    # LLM → plan
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    plan = [] if looks_empty_diff(diff_json) else llm_plan_from_diff(client, diff_json)
    with open(args.plan, "w") as f: json.dump(plan, f, indent=2)

    # Build collection
    pm_collection = build_postman_collection(args.collection, plan)

    # Postman MCP integration
    mcp = McpHttp(os.environ["POSTMAN_MCP_URL"], os.environ["POSTMAN_API_KEY"])
    ws_obj = call_tool(mcp, "getWorkspaces", {})
    ws_list = normalize_workspaces(ws_obj)
    ws_name = os.environ.get("POSTMAN_WORKSPACE_NAME", "Security Demo")
    ws = next((w for w in ws_list if w.get("name") == ws_name), None)
    if not ws:
        raise SystemExit(f"Workspace {ws_name} not found.")
    workspace_id = ws["id"]

    # Delete old collection (idempotent)
    try:
        existing = call_tool(mcp, "searchCollections", {"workspace": workspace_id, "query": args.collection})
        if existing.get("items"):
            cid0 = existing["items"][0]["id"]
            call_tool(mcp, "deleteCollection", {"collectionId": cid0})
    except Exception:
        pass

    # Create new collection
    created = call_tool(mcp, "createCollection", {"workspace": workspace_id, "collection": pm_collection})
    cid = collection_id_from_create(created)
    if not cid:
        raise SystemExit(f"Could not resolve collection id: {created}")

    # Get full collection JSON
    got = call_tool(mcp, "getCollection", {"collectionId": cid})
    collection_obj = got.get("collection") if isinstance(got, dict) and "collection" in got else got
    with open("generated-security-test.postman_collection.json", "w") as f:
        json.dump(collection_obj, f, indent=2)
    print("MCP: collection created & fetched.")

    # Ensure environment (tokens & defaults)
    env_name = "Local Security Test"
    env_vars = [
        {"key": "baseUrl", "value": "http://127.0.0.1:8000"},
        {"key": "token_user1", "value": "token-user-u1"},
        {"key": "token_user2", "value": "token-user-u2"},
        {"key": "token_admin", "value": "token-admin"},
        {"key": "id", "value": "p1"},
    ]
    try:
        env = {"name": env_name, "values": env_vars}
        # Best effort create; ignore if it already exists
        call_tool(mcp, "createEnvironment", {"workspace": workspace_id, "environment": env})
    except Exception as e:
        print(f"[WARN] could not create env: {e}")

if __name__ == "__main__":
    main()
