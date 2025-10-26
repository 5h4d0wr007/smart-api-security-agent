import os, json, sys, subprocess, argparse, re, time
from typing import Any, Dict, List, Optional
from mcp_client import McpHttp
from openai import OpenAI


# ----------------- shell helper -----------------
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
        "Generate tests for OWASP API Top10 risks: "
        "- Missing Auth (401) "
        "- BOLA/BOPLA (403/404) "
        "- BFLA (403) "
        "- Success (2xx). "
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


# ----------------- Build Postman Collection -----------------
def build_postman_collection(collection_name: str, plan: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Generates unauth / owner / cross-tenant test variants per endpoint."""
    def norm(ep: str) -> str:
        ep = ep or "/"
        if not ep.startswith("/"):
            ep = "/" + ep
        return re.sub(r"\{([^}/]+)\}", r"{{\1}}", ep)

    def path_vars(ep: str) -> List[str]:
        return re.findall(r"\{\{([^}/]+)\}\}", norm(ep))

    def id_map_for(var: str) -> tuple[str, str]:
        m = var.lower()
        if "user" in m: return "{{user_owner}}", "{{user_other}}"
        if "account" in m: return "{{account_owner}}", "{{account_other}}"
        if "order" in m: return "{{order_owner}}", "{{order_other}}"
        return "{{id_owner}}", "{{id_other}}"

    def replace_ids(ep: str, owner: bool) -> str:
        e = norm(ep)
        for v in path_vars(e):
            own, oth = id_map_for(v)
            e = e.replace("{{"+v+"}}", own if owner else oth)
        return e

    def add_expect_from_label(script: List[str], lbl: str):
        s = lbl.lower()
        if "unauth" in s or "401" in s: script.append('expect(401, "Unauthenticated -> 401");'); return
        if "forbidden" in s or "bfla" in s or "403" in s: script.append('expect(403, "Forbidden -> 403");'); return
        if "idor" in s or "bola" in s or "404" in s or "not found" in s: script.append('expect(404, "Not found -> 404");'); return
        if "400" in s or "invalid" in s: script.append('expect(400, "Invalid -> 400");'); return
        if "409" in s or "conflict" in s: script.append('expect(409, "Replay/Conflict -> 409");'); return
        if "202" in s or "accepted" in s: script.append('expect(202, "Accepted -> 202");'); return
        if "201" in s or "created" in s: script.append('expect(201, "Created -> 201");'); return
        if "200" in s or "ok" in s: script.append('expect(200, "OK -> 200");'); return

    def add_expect_from_dict(script: List[str], d: Dict[str, Any]):
        label = d.get("name") or d.get("label") or ""
        status = d.get("expect") or d.get("expectStatus") or d.get("status")
        type_hint = str(d.get("type") or "").lower()
        map_ = {
            "unauth": (401, "Unauthenticated -> 401"),
            "bfla": (403, "Forbidden -> 403"),
            "bola": (404, "Not found -> 404"),
            "forbidden": (403, "Forbidden -> 403"),
            "invalid": (400, "Invalid -> 400"),
            "conflict": (409, "Replay/Conflict -> 409"),
            "accepted": (202, "Accepted -> 202"),
            "created": (201, "Created -> 201"),
            "ok": (200, "OK -> 200"),
        }
        if type_hint in map_:
            st, lab = map_[type_hint]
            script.append(f'expect({st}, "{lab}");'); return
        if isinstance(status, (int, float)):
            st = int(status)
            lab = label or f"Expect -> {st}"
            script.append(f'expect({st}, "{lab}");'); return
        if label:
            add_expect_from_label(script, label); return
        script.append('pm.test("Generic check", () => pm.expect([200,201,202,400,401,403,404,409]).to.include(code));')

    def pm_item(name: str, method: str, endpoint: str, token_expr: str, tests: Any) -> Dict[str, Any]:
        path_parts = endpoint.lstrip("/").split("/") if endpoint != "/" else []
        url = {"raw": "{{baseUrl}}"+endpoint, "host": ["{{baseUrl}}"], "path": path_parts}
        headers = [
            {"key":"Authorization","value": f"Bearer {token_expr}","type":"text"},
            {"key":"Content-Type","value":"application/json","type":"text"},
        ]
        script = [
            "const code = pm.response.code;",
            "function expect(c, name){ pm.test(name, () => pm.expect(code).to.eql(c)); }",
        ]
        seq = tests if isinstance(tests, list) else ([] if tests is None else [tests])
        added = False
        for t in seq:
            if isinstance(t, str): add_expect_from_label(script, t); added = True
            elif isinstance(t, (int,float)): add_expect_from_dict(script, {"status": int(t)}); added = True
            elif isinstance(t, dict): add_expect_from_dict(script, t); added = True
        if not added:
            script.append('pm.test("Generic check", () => pm.expect([200,201,202,400,401,403,404,409]).to.include(code));')
        return {
            "name": name,
            "request": {"method": method, "header": headers, "url": url, "body":{"mode":"raw","raw":"{}"}},
            "event":[{"listen":"test","script":{"type":"text/javascript","exec":script}}]
        }

    items: List[Dict[str,Any]] = []
    for r in plan or []:
        if not isinstance(r, dict): continue
        if (r.get("changeType") or "").lower() == "deleted": continue
        ep = r.get("endpoint") or "/"
        method = (r.get("method") or "GET").upper()
        ep_norm = norm(ep)
        ep_owner = replace_ids(ep, True)
        ep_other = replace_ids(ep, False)
        # unauth
        items.append(pm_item(f"(unauth) {method} {ep_norm}", method, ep_norm, "{{token_none}}", ["Unauthenticated -> 401"]))
        # owner
        items.append(pm_item(f"(owner) {method} {ep_norm}", method, ep_owner, "{{token_owner}}", ["OK -> 200"]))
        # cross-tenant
        items.append(pm_item(f"(x-tenant) {method} {ep_norm}", method, ep_other, "{{token_owner}}", ["Forbidden -> 403", "Not found -> 404"]))

    if not items:
        items.append(pm_item("(owner) GET /me", "GET", "/me", "{{token_owner}}", ["OK -> 200"]))

    return {
        "info": {"name": collection_name, "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": items,
        "variable": [
            {"key":"baseUrl","value":"http://127.0.0.1:8000"},
            {"key":"token_none","value":""},
            {"key":"token_owner","value":"t1"},
            {"key":"token_other","value":"t2"},
            {"key":"token_admin","value":"ta"},
            {"key":"user_owner","value":"1"},
            {"key":"user_other","value":"2"},
            {"key":"account_owner","value":"101"},
            {"key":"account_other","value":"102"},
            {"key":"order_owner","value":"201"},
            {"key":"order_other","value":"202"},
            {"key":"id_owner","value":"1"},
            {"key":"id_other","value":"2"}
        ]
    }


# ----------------- MCP helpers -----------------
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

    run(["swagger-cli", "validate", args.base])
    run(["swagger-cli", "validate", args.head])
    diff_json = run(["oasdiff", "diff", "--format", "json", args.base, args.head])
    with open(args.diff, "w") as f: f.write(diff_json)

    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    plan = [] if looks_empty_diff(diff_json) else llm_plan_from_diff(client, diff_json)
    with open(args.plan, "w") as f: json.dump(plan, f, indent=2)

    pm_collection = build_postman_collection(args.collection, plan)

    mcp = McpHttp(os.environ["POSTMAN_MCP_URL"], os.environ["POSTMAN_API_KEY"])
    ws_obj = call_tool(mcp, "getWorkspaces", {})
    ws_list = normalize_workspaces(ws_obj)
    ws_name = os.environ.get("POSTMAN_WORKSPACE_NAME", "Security Demo")
    ws = next((w for w in ws_list if w.get("name") == ws_name), None)
    if not ws:
        raise SystemExit(f"Workspace {ws_name} not found.")
    workspace_id = ws["id"]

    try:
        existing = call_tool(mcp, "searchCollections", {"workspace": workspace_id, "query": args.collection})
        if existing.get("items"):
            cid0 = existing["items"][0]["id"]
            call_tool(mcp, "deleteCollection", {"collectionId": cid0})
    except Exception:
        pass

    created = call_tool(mcp, "createCollection", {"workspace": workspace_id, "collection": pm_collection})
    cid = collection_id_from_create(created)
    if not cid:
        raise SystemExit(f"Could not resolve collection id: {created}")

    got = call_tool(mcp, "getCollection", {"collectionId": cid})
    collection_obj = got.get("collection") if isinstance(got, dict) and "collection" in got else got
    with open("generated-security-test.postman_collection.json", "w") as f:
        json.dump(collection_obj, f, indent=2)
    print("MCP: collection created & fetched.")

    env_name = "Local Security Test"
    env_vars = [
        {"key":"baseUrl","value":"http://127.0.0.1:8000"},
        {"key":"token_none","value":""},
        {"key":"token_owner","value":"t1"},
        {"key":"token_other","value":"t2"},
        {"key":"token_admin","value":"ta"},
        {"key":"user_owner","value":"1"},
        {"key":"user_other","value":"2"},
        {"key":"account_owner","value":"101"},
        {"key":"account_other","value":"102"},
        {"key":"order_owner","value":"201"},
        {"key":"order_other","value":"202"},
        {"key":"id_owner","value":"1"},
        {"key":"id_other","value":"2"},
    ]
    try:
        env = {"name": env_name, "values": env_vars}
        call_tool(mcp, "createEnvironment", {"workspace": workspace_id, "environment": env})
    except Exception as e:
        print(f"[WARN] could not create env: {e}")

if __name__ == "__main__":
    main()
