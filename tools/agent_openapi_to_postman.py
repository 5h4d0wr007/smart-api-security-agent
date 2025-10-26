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
            sys.stderr.write(f"[WARN] parse fail ({e}), retrying...\n")
            time.sleep(1)
    return []

def build_postman_collection(collection_name: str, plan: List[Dict[str, Any]]) -> Dict[str, Any]:
    def normalize_endpoint(ep: str) -> str:
        ep = ep or "/"
        if not ep.startswith("/"):
            ep = "/" + ep
        ep = re.sub(r"\{([^}/]+)\}", r"{{\1}}", ep)
        return ep

    def pm_item(endpoint: str, method: str, tests: List[str]) -> Dict[str, Any]:
        endpoint = normalize_endpoint(endpoint)
        path_parts = endpoint.lstrip("/").split("/") if endpoint != "/" else []
        url = {"raw": "{{baseUrl}}" + endpoint, "host": ["{{baseUrl}}"], "path": path_parts}
        headers = [
            {"key": "Authorization", "value": "Bearer {{token}}", "type": "text"},
            {"key": "Content-Type", "value": "application/json", "type": "text"},
        ]
        script = [
            "const code = pm.response.code;",
            "function expect(c, name){ pm.test(name, () => pm.expect(code).to.eql(c)); }",
        ]
        for t in tests or []:
            s = t.lower()
            if "unauth" in s: script.append('expect(401, "Unauthenticated -> 401");')
            elif "forbidden" in s or "role" in s: script.append('expect(403, "Forbidden -> 403");')
            elif "invalid" in s or "bad request" in s: script.append('expect(400, "Invalid -> 400");')
            elif "conflict" in s: script.append('expect(409, "Conflict -> 409");')
            elif "not found" in s: script.append('expect(404, "Not found -> 404");')
            elif "202" in s: script.append('expect(202, "Accepted -> 202");')
            elif "201" in s: script.append('expect(201, "Created -> 201");')
            elif "200" in s: script.append('expect(200, "OK -> 200");')
        return {
            "name": f"{method} {endpoint}",
            "request": {"method": method, "header": headers,
                        "url": url, "body": {"mode": "raw", "raw": "{}"}},
            "event": [{"listen": "test", "script": {"type": "text/javascript", "exec": script}}]
        }

    items = [pm_item(r.get("endpoint"), (r.get("method") or "GET").upper(), r.get("tests"))
             for r in plan if r.get("changeType") != "deleted"]

    if not items:
        items = [pm_item("/", "GET", ["OK -> 200"])]

    return {
        "info": {"name": collection_name, "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": items,
        "variable": [
            {"key": "baseUrl", "value": "http://127.0.0.1:8000"},
            {"key": "token", "value": "token-user-u1"},
            {"key": "id", "value": "p1"}
        ]
    }

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

    # Ensure environment (tokens)
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
        call_tool(mcp, "createEnvironment", {"workspace": workspace_id, "environment": env})
    except Exception as e:
        print(f"[WARN] could not create env: {e}")

if __name__ == "__main__":
    main()
