# tools/agent_openapi_to_postman.py
import os, json, sys, subprocess, argparse, re, time
from typing import Any, Dict, List
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
    # Try ```json ... ``` blocks
    m = re.search(r"```json\s*([\s\S]*?)```", s, re.IGNORECASE)
    if m:
        return json.loads(m.group(1))
    # Try any {...} top-level JSON object
    m = re.search(r"(\{[\s\S]*\})", s)
    if m:
        return json.loads(m.group(1))
    # Try any [...] array
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

    # Prefer JSON mode (requires newer OpenAI APIs)
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
            # JSON mode returns an object; we expect array; accept either and normalize
            data = parse_json_strict(content)
            if isinstance(data, dict) and "items" in data:
                data = data["items"]
            if isinstance(data, dict):
                # try to coerce to array if the model returned {plan:[...]} etc.
                for k, v in data.items():
                    if isinstance(v, list):
                        data = v
                        break
            if not isinstance(data, list):
                raise ValueError("Model did not return a JSON array")
            return data
        except Exception as e:
            last_err = e
            # Fallback: try without json mode and extract from fences
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
    # Final fallback
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

    # If plan is empty, include a tiny health-check to make runs/noise obvious
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

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="openapi/api.v1.yaml")
    ap.add_argument("--head", default="openapi/api.yaml")
    ap.add_argument("--diff", default="diff.json")
    ap.add_argument("--collection", default="security test collection")
    ap.add_argument("--plan", default="plan.json")
    args = ap.parse_args()

    # 1) Validate & diff (already done in CI step too, but harmless here)
    run(["swagger-cli", "validate", args.base])
    run(["swagger-cli", "validate", args.head])
    diff_json = run(["oasdiff", "diff", "--format", "json", args.base, args.head])
    with open(args.diff, "w") as f: f.write(diff_json)

    # 2) LLM → plan (robust)
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])
    if looks_empty_diff(diff_json):
        plan = []
    else:
        plan = llm_plan_from_diff(client, diff_json)
    with open(args.plan, "w") as f: json.dump(plan, f, indent=2)

    # 3) Build collection
    pm_collection = build_postman_collection(args.collection, plan)

    # 4) Official Postman MCP (remote): workspace by NAME, CRUD+export collection
    mcp = McpHttp(os.environ["POSTMAN_MCP_URL"], os.environ["POSTMAN_API_KEY"])

    workspaces = mcp.call_tool("getWorkspaces", {})
    ws_name = os.environ.get("POSTMAN_WORKSPACE_NAME","Security Demo")
    ws = next((w for w in workspaces.get("items",[]) if w.get("name")==ws_name), None)
    if not ws: raise SystemExit(f"Workspace not found: {ws_name}")
    workspace_id = ws["id"]

    existing = mcp.call_tool("searchCollections", {"workspaceId": workspace_id, "query": args.collection})
    if existing.get("items"):
        mcp.call_tool("deleteCollection", {"id": existing["items"][0]["id"]})
    created = mcp.call_tool("createCollection", {"workspaceId": workspace_id, "name": args.collection})
    mcp.call_tool("updateCollection", {"id": created["collection"]["id"], "collection": pm_collection})

    exported = mcp.call_tool("exportCollection", {"id": created["collection"]["id"], "format": "v2.1"})
    with open("generated-security-test.postman_collection.json","w") as f:
        json.dump(exported["collection"], f, indent=2)

    print("MCP: collection created & exported.")

if __name__ == "__main__":
    main()
