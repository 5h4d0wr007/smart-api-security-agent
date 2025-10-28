import os
import json
import argparse
from typing import Any, Dict, List, Tuple

from openai import OpenAI  # pip install openai>=2
from mcp_client import PostmanMCPClient


OWASP_TOP10 = [
    "API1:2023 – Broken Object Level Authorization (BOLA)",
    "API2:2023 – Broken Authentication",
    "API3:2023 – Broken Object Property Level Authorization (BOPLA)",
    "API4:2023 – Unrestricted Resource Consumption",
    "API5:2023 – Broken Function Level Authorization (BFLA)",
    "API6:2023 – Unrestricted Access to Sensitive Business Flows",
    "API7:2023 – Server Side Request Forgery",
    "API8:2023 – Security Misconfiguration",
    "API9:2023 – Improper Inventory Management",
    "API10:2023 – Unsafe Consumption of APIs",
]


def load_file(p: str) -> str:
    with open(p, "r", encoding="utf-8") as f:
        return f.read()


def read_json(p: str) -> Any:
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(p: str, obj: Any) -> None:
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def llm_plan_and_tests(openai_key: str, base_spec: str, head_spec: str, diff_json: Dict[str, Any]) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Ask the LLM to:
      1) Identify risks (OWASP API Top 10 inspired) from the HEAD spec and diff.
      2) Emit a Postman collection with executable tests and dynamic variables ({{userId}}, etc.).
    """
    client = OpenAI(api_key=openai_key)

    sys = (
        "You are an API security expert. Generate targeted security tests from an OpenAPI spec and its diff. "
        "Focus on OWASP API Top 10. Emit a valid Postman v2.1 collection that uses dynamic variables and sets "
        "pm.test(...) assertions to validate expected security behavior. Use auth headers or cookies as variables "
        "({{ownerToken}}, {{xTenant}}, etc.). Where path parameters exist, reference Postman variables like "
        "{{userId}}, and add pre-request scripts to set them when needed."
    )

    user = {
        "base_spec": base_spec,
        "head_spec": head_spec,
        "diff": diff_json,
        "owasp": OWASP_TOP10,
        "expectations": [
            "Include negative tests for BOLA/BOPLA/BFLA using two users: user 1 (owner) and user 2 (other).",
            "Use environment vars: ownerUserId=1, otherUserId=2, ownerToken=t1, otherToken=t2.",
            "Replace any {id}-style path params with Postman variables in the request URL (e.g., /users/{{userId}}/profile).",
            "Assertions should check 401 for unauthenticated, 403 for cross-tenant/role violations, 200/202 for owner-allowed.",
            "If an endpoint doesn’t exist, assert 404 to mark gap.",
        ],
    }

    # Use a response_format so we can parse reliably
    completion = client.chat.completions.create(
        model="gpt-4o-mini",
        temperature=0.2,
        messages=[
            {"role": "system", "content": sys},
            {"role": "user", "content": json.dumps(user)},
        ],
        response_format={"type": "json_object"},
    )

    content = completion.choices[0].message.content
    try:
        data = json.loads(content)
    except Exception:
        # If the model didn't return strict JSON, wrap it as reason
        data = {"plan": {"notes": "Non-JSON from LLM", "raw": content}, "postman_collection": {}}

    plan = data.get("plan") or {
        "summary": "Security plan generated",
        "risks": [],
        "notes": "No plan chunk present from LLM.",
    }
    collection = data.get("postman_collection") or {}

    # Ensure collection info and schema
    info = collection.setdefault("info", {})
    info.setdefault("name", "security test collection")
    info.setdefault("_postman_id", "auto-generated")
    info.setdefault("schema", "https://schema.getpostman.com/json/collection/v2.1.0/collection.json")

    # Ensure some items exist
    collection.setdefault("item", [])
    # Add a fallback environment bootstrap in a top-level event, so Postman variables exist
    events = collection.setdefault("event", [])
    bootstrap_script = (
        "if (!pm.environment.get('ownerUserId')) { pm.environment.set('ownerUserId', '1'); }\n"
        "if (!pm.environment.get('otherUserId')) { pm.environment.set('otherUserId', '2'); }\n"
        "if (!pm.environment.get('ownerToken')) { pm.environment.set('ownerToken', 't1'); }\n"
        "if (!pm.environment.get('otherToken')) { pm.environment.set('otherToken', 't2'); }\n"
        "if (!pm.environment.get('baseUrl')) { pm.environment.set('baseUrl', 'http://127.0.0.1:8000'); }\n"
        "pm.globals.set('userId', pm.environment.get('ownerUserId'));\n"
        "pm.globals.set('accountId', '101');\n"
        "pm.globals.set('orderId', '201');\n"
    )
    events.append({
        "listen": "prerequest",
        "script": {"type": "text/javascript", "exec": bootstrap_script.splitlines()},
    })

    return plan, collection


def select_workspace_id(mcp: PostmanMCPClient, desired_name: Optional[str]) -> str:
    ws = mcp.get_workspaces() or {}
    arr = ws.get("workspaces") or []
    if desired_name:
        for w in arr:
            if w.get("name") == desired_name:
                return w.get("id")
    # default to first
    if not arr:
        raise RuntimeError("No Postman workspaces visible via MCP")
    return arr[0].get("id")


def find_existing_collection_id(mcp: PostmanMCPClient, workspace_id: str, name: str) -> Optional[str]:
    cols = mcp.get_collections(workspace_id) or {}
    for c in cols.get("collections", []):
        if (c.get("name") or "").strip().lower() == name.strip().lower():
            return c.get("id")
    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--base", required=True, help="path to base OpenAPI spec")
    parser.add_argument("--head", required=True, help="path to head OpenAPI spec")
    parser.add_argument("--diff", required=False, default="diff.json", help="path to diff JSON (optional)")
    parser.add_argument("--collection", required=False, default="security test collection", help="desired collection name")
    parser.add_argument("--plan", required=False, default="plan.json", help="path to write the plan JSON")
    args = parser.parse_args()

    openai_key = os.getenv("OPENAI_API_KEY")
    if not openai_key:
        raise RuntimeError("OPENAI_API_KEY must be set")

    postman_url = os.getenv("POSTMAN_MCP_URL")
    postman_key = os.getenv("POSTMAN_API_KEY")
    if not postman_url or not postman_key:
        raise RuntimeError("POSTMAN_MCP_URL and POSTMAN_API_KEY must be set")

    base_spec = load_file(args.base)
    head_spec = load_file(args.head)
    diff_json = {}
    if os.path.exists(args.diff):
        try:
            diff_json = read_json(args.diff)
        except Exception:
            diff_json = {}

    print("[agent] Calling LLM for risk and test generation...")
    plan, collection = llm_plan_and_tests(openai_key, base_spec, head_spec, diff_json)
    write_json(args.plan, plan)

    # Always make sure requests use {{baseUrl}} and variables where possible
    for item in collection.get("item", []):
        req = item.get("request") or {}
        if isinstance(req.get("url"), str):
            url = req["url"]
            # promote hardcoded host to {{baseUrl}}
            if url.startswith("http://127.0.0.1:8000"):
                req["url"] = url.replace("http://127.0.0.1:8000", "{{baseUrl}}")
        elif isinstance(req.get("url"), dict):
            u = req["url"]
            if isinstance(u.get("raw"), str) and "http://127.0.0.1:8000" in u["raw"]:
                u["raw"] = u["raw"].replace("http://127.0.0.1:8000", "{{baseUrl}}")

    # Persist locally for Postman CLI run
    write_json("generated-security-test.postman_collection.json", collection)

    # Sync with MCP (create or update, but handle lack of update tool)
    print("[agent] Pushing generated collection to Postman MCP...")
    mcp = PostmanMCPClient(base_url=postman_url, api_key=postman_key)
    ws_name = os.getenv("POSTMAN_WORKSPACE_NAME")
    workspace_id = select_workspace_id(mcp, ws_name)

    desired_name = args.collection or "security test collection"
    collection["info"]["name"] = desired_name
    existing_id = find_existing_collection_id(mcp, workspace_id, desired_name)

    # The key change: use upsert with fallback (no updateCollection dependency)
    mcp.upsert_collection(workspace_id, collection, existing_id=existing_id)

    print("[agent] plan.json + collection generated and synced with MCP.")


if __name__ == "__main__":
    main()
