import os, json, sys, subprocess, argparse
from mcp_client import McpHttp
from openai import OpenAI

def run(cmd):
    print("+", " ".join(cmd), flush=True)
    cp = subprocess.run(cmd, capture_output=True, text=True)
    if cp.returncode != 0:
        print(cp.stdout)
        print(cp.stderr)
        raise SystemExit(cp.returncode)
    return cp.stdout

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="openapi/api.v1.yaml")
    ap.add_argument("--head", default="openapi/api.yaml")
    ap.add_argument("--diff", default="diff.json")
    ap.add_argument("--collection", default="security test collection")
    ap.add_argument("--plan", default="plan.json")
    args = ap.parse_args()

    # 1) Validate & diff OpenAPI (using oasdiff CLI for CI-friendly JSON)
    run(["swagger-cli", "validate", args.base])
    run(["swagger-cli", "validate", args.head])
    diff_json = run(["oasdiff", "diff", "--format", "json", args.base, args.head])
    with open(args.diff, "w") as f: f.write(diff_json)

    # 2) LLM: diff -> security test plan
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    system = (
        "You are an API security reviewer for CI. "
        "Input: oasdiff JSON. "
        "Output: JSON array of items {endpoint, method, changeType:added|modified|deleted, risks[], tests[]}. "
        "Focus on authn/authz, IDOR, input validation, idempotency (409), rate limiting, and happy-path 2xx where relevant. "
        "Return ONLY JSON."
    )
    user = diff_json[:120000]
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        temperature=0.1,
        messages=[{"role":"system","content":system},{"role":"user","content":user}]
    )
    content = resp.choices[0].message.content
    plan = json.loads(content)
    with open(args.plan, "w") as f: json.dump(plan, f, indent=2)

    # 3) Build Postman collection (v2.1) locally
    def pm_item(endpoint, method, tests):
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
        for t in (tests or []):
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

    items = []
    for r in plan:
        if r.get("changeType") == "deleted": continue
        items.append(pm_item(r["endpoint"], (r.get("method") or "GET").upper(), r.get("tests")))

    collection = {
        "info": {"name": args.collection, "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item": items,
        "variable": [
            {"key":"baseUrl","value":"http://127.0.0.1:8000"},
            {"key":"token","value":"demo-token"}
        ]
    }

    # 4) Official Postman MCP (remote): resolve workspace by NAME, CRUD+export collection
    mcp = McpHttp(os.environ["POSTMAN_MCP_URL"], os.environ["POSTMAN_API_KEY"])

    # Resolve workspace by name
    workspaces = mcp.call_tool("getWorkspaces", {})
    ws_name = os.environ.get("POSTMAN_WORKSPACE_NAME","Security Demo")
    ws = next((w for w in workspaces.get("items",[]) if w.get("name")==ws_name), None)
    if not ws: raise SystemExit(f"Workspace not found: {ws_name}")
    workspace_id = ws["id"]

    # Delete existing collection (override) & create new
    existing = mcp.call_tool("searchCollections", {"workspaceId": workspace_id, "query": args.collection})
    if existing.get("items"): mcp.call_tool("deleteCollection", {"id": existing["items"][0]["id"]})
    created = mcp.call_tool("createCollection", {"workspaceId": workspace_id, "name": args.collection})
    mcp.call_tool("updateCollection", {"id": created["collection"]["id"], "collection": collection})

    # Export for Postman CLI run
    exported = mcp.call_tool("exportCollection", {"id": created["collection"]["id"], "format": "v2.1"})
    with open("generated-security-test.postman_collection.json","w") as f:
        json.dump(exported["collection"], f, indent=2)

    print("MCP: collection created & exported.")

if __name__ == "__main__":
    main()
