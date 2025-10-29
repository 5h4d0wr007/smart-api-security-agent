#!/usr/bin/env python3
"""
agent_openapi_to_postman.py

Generates a *security-focused* Postman collection from OpenAPI changes using an LLM
and pushes/overwrites it via Postman MCP. This version hardens the prompt so that
tests ONLY cover three practical authorization scenarios per endpoint:

  1) (unauth)  -> expect 401
  2) (owner)   -> expect 200 with owned IDs
  3) (x-tenant)-> expect 403 or 404 when using someone else's IDs

It also enforces strict item naming so downstream CI can reliably filter findings
to *only* security failures (unauth/x-tenant), and never surface “happy-path”
owner tests in the PR comment.

Inputs (args):
  --base <path>        Path to base OpenAPI (previous version)
  --head <path>        Path to head OpenAPI (current)
  --diff <path>        Path to oasdiff JSON (may be `{}`)
  --collection <name>  Postman collection name to overwrite
  --plan <path>        Where to write the LLM test plan (json)

Requires env:
  OPENAI_API_KEY, POSTMAN_API_KEY, POSTMAN_MCP_URL, POSTMAN_WORKSPACE_NAME, POSTMAN_ENV_NAME
"""

import argparse
import json
import os
import sys
from textwrap import dedent
from string import Template
import requests

# ---- Helpers -----------------------------------------------------------------

def load_text(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()

def save_json(p, obj):
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)

def getenv_strict(name):
    val = os.getenv(name)
    if not val:
        print(f"[agent] Missing required env: {name}", file=sys.stderr)
        sys.exit(2)
    return val

def post_json(url, payload, headers=None):
    h = {"Content-Type": "application/json"}
    if headers:
        h.update(headers)
    resp = requests.post(url, data=json.dumps(payload), headers=h, timeout=60)
    resp.raise_for_status()
    return resp.json()

# ---- Prompt (HARDENED) -------------------------------------------------------

PROMPT_SYSTEM = dedent("""
You are a Security Test Agent specialized in generating **practical authorization tests** from OpenAPI specs.
Return output ONLY in the JSON schema I ask for—no prose.
The generated tests must be **minimal, deterministic, and CI-friendly**.
Do NOT invent endpoints. Only consider endpoints that changed according to the provided oasdiff or that exist in the HEAD spec.
""").strip()

# IMPORTANT: Using Template ($vars) to avoid brace-escaping issues.
PROMPT_USER_TPL = Template("""
You are given:
- BASE OpenAPI (previous version)
- HEAD OpenAPI (current version)
- OASDIFF (JSON)

Goal: Produce a *security test plan* for **only the endpoints added or changed**.
For each qualifying endpoint+method, generate **up to 3 requests**, one per scenario:

SCENARIOS (strict):
1) (unauth)  -> send NO Authorization header  -> EXPECT status 401
2) (owner)   -> use {{token_owner}} and OWNED ids -> EXPECT status 200
3) (x-tenant)-> use {{token_owner}} but OTHER user's ids -> EXPECT status 403 or 404

STRICT RULES:
- Name each request EXACTLY with prefix in parentheses: "(unauth) ", "(owner) ", "(x-tenant) ".
- Never include other scenarios. Never generate "(admin)" or similar.
- Prefer a single representative example per unique **resource path**; do not explode combinatorics.
- Use realistic example path params and bodies. Keep bodies tiny.
- Use JSON, set Content-Type: application/json when applicable.
- For HEAD/GET without body, omit body.
- If endpoint obviously public (e.g., /health), skip it.
- If the endpoint is clearly read-only and *object ownership* is not meaningful, you may skip (owner)/(x-tenant) and only produce (unauth) if auth is required.
- Produce 403 OR 404 for (x-tenant) depending on what is **more conservative** for security (prefer 403).
- Include test assertions as simple "expectedStatus": <code> only. No schema assertions.

VARIABLES and TOKENS (do NOT hardcode bearer values):
- Use an environment variable {{baseUrl}} for host, e.g. {{baseUrl}}/orders/201/cancel
- Use {{token_owner}} for the owner token in Authorization header: "Bearer {{token_owner}}"
- For (unauth), either omit Authorization or set "Bearer " (empty).
- Use the following IDs to ensure reproducible tests in our sample app:
  * user ids: owner=1, other=2
  * account ids: owner=101, other=102
  * order ids: owner=201, other=202

OUTPUT JSON SCHEMA (MUST MATCH EXACTLY):

{
  "items": [
    {
      "name": "(unauth) POST /orders/202/cancel",
      "request": {
        "method": "POST",
        "url": "{{baseUrl}}/orders/202/cancel",
        "headers": [{"key":"Content-Type","value":"application/json"}],
        "body": {"mode":"raw","raw":"{}"}
      },
      "expectedStatus": 401
    }
  ]
}

Constraints:
- Keep between 1 and 20 items total.
- Only include endpoints that exist in HEAD and are added/changed per oasdiff; fall back to HEAD if diff is empty.
- Use provided ids consistently to represent owner vs cross-tenant attempts.
- Absolutely no extra keys or commentary—return a single JSON object.
--- BASE OPENAPI ---
$base_spec
--- HEAD OPENAPI ---
$head_spec
--- OASDIFF ---
$diff_json
""")

# ---- Build Postman collection from plan --------------------------------------

def plan_to_postman_collection(plan_items, collection_name):
    """
    Convert plan to a minimal Postman collection with request-level tests
    that assert only on status code, and with enforced item naming.
    """
    allowed_prefixes = ("(unauth) ", "(owner) ", "(x-tenant) ")
    clean_items = []
    for it in plan_items:
        name = (it.get("name") or "").strip()
        if not any(name.startswith(p) for p in allowed_prefixes):
            continue
        clean_items.append(it)

    pm_items = []
    for it in clean_items:
        req = it["request"]
        expected = int(it["expectedStatus"])
        test_name = it["name"]

        # JS test asserts only status
        test_script = f"""pm.test("{test_name}", function() {{
  pm.expect(pm.response.code).to.eql({expected});
}});"""

        # Rebuild URL components for Postman
        raw_url = req["url"]
        path = raw_url.replace("{{baseUrl}}/","").split("/")
        pm_items.append({
            "name": test_name,
            "request": {
                "method": req["method"],
                "header": req.get("headers", []),
                "url": {
                    "raw": raw_url,
                    "host": ["{{baseUrl}}"],
                    "path": path
                },
                **({"body": req["body"]} if "body" in req else {})
            },
            "event": [{
                "listen": "test",
                "script": {"type":"text/javascript", "exec": test_script.splitlines()}
            }]
        })

    collection = {
        "info": {
            "name": collection_name,
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": pm_items,
        "variable": [
            {"key":"baseUrl","value":"http://127.0.0.1:8000"},
            {"key":"token_owner","value":"t1"}
        ]
    }
    return collection

# ---- LLM + MCP glue ----------------------------------------------------------

def call_openai_for_plan(base_spec, head_spec, diff_json):
    api_key = getenv_strict("OPENAI_API_KEY")
    model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")

    url = "https://api.openai.com/v1/responses"
    payload = {
        "model": model,
        "input": [
            {"role":"system","content": PROMPT_SYSTEM},
            {"role":"user","content": PROMPT_USER_TPL.safe_substitute(
                base_spec=base_spec, head_spec=head_spec, diff_json=diff_json
            )}
        ],
        "temperature": 0.0
    }
    headers = {"Authorization": f"Bearer {api_key}"}
    print("[agent] Calling LLM for security test plan...")
    data = post_json(url, payload, headers=headers)

    # Extract text robustly across response variants
    text = ""
    try:
        text = data["output"][0]["content"][0]["text"]
    except Exception:
        text = data.get("output_text") or data.get("content") or ""

    try:
        plan = json.loads(text)
    except Exception:
        print("[agent] Failed to parse LLM JSON. Raw (first 600 chars):", text[:600], file=sys.stderr)
        raise

    if "items" not in plan or not isinstance(plan["items"], list):
        raise RuntimeError("LLM plan missing `items` array.")
    return plan

def push_collection_via_mcp(collection_json, collection_name):
    """
    Use official Postman MCP REST to upsert the collection into the target workspace/env.
    Requires POSTMAN_MCP_URL, POSTMAN_API_KEY, POSTMAN_WORKSPACE_NAME, POSTMAN_ENV_NAME.
    """
    mcp_url   = getenv_strict("POSTMAN_MCP_URL").rstrip("/")
    api_key   = getenv_strict("POSTMAN_API_KEY")
    ws_name   = getenv_strict("POSTMAN_WORKSPACE_NAME")
    env_name  = getenv_strict("POSTMAN_ENV_NAME")

    payload = {
        "action": "upsertCollection",
        "workspaceName": ws_name,
        "environmentName": env_name,
        "collectionName": collection_name,
        "collection": collection_json
    }
    headers = {"X-Api-Key": api_key}
    print("[agent] Pushing generated collection to Postman MCP...")
    resp = post_json(f"{mcp_url}/api/ci/security-collection", payload, headers=headers)
    return resp

# ---- Main --------------------------------------------------------------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--diff", required=True)
    ap.add_argument("--collection", required=True)
    ap.add_argument("--plan", required=True)
    args = ap.parse_args()

    base_spec = load_text(args.base)
    head_spec = load_text(args.head)
    diff_json = load_text(args.diff)

    # 1) Ask LLM for tight security plan
    plan = call_openai_for_plan(base_spec, head_spec, diff_json)
    save_json(args.plan, plan)
    print(f"[agent] Wrote plan to {args.plan} with {len(plan.get('items',[]))} items")

    # 2) Convert plan → Postman collection (with strict naming + env vars)
    collection = plan_to_postman_collection(plan["items"], args.collection)
    save_json("generated-security-test.postman_collection.json", collection)
    print("[agent] Generated Postman collection at generated-security-test.postman_collection.json")

    # 3) Upsert via MCP (non-fatal if it fails)
    try:
        _ = push_collection_via_mcp(collection, args.collection)
    except Exception as e:
        print("[agent] MCP push error (non-fatal):", str(e), file=sys.stderr)

    print("[agent] Done.")

if __name__ == "__main__":
    main()
