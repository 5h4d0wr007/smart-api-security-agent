#!/usr/bin/env python3
"""
LLM-only API Security Agent

- Reads:  --diff (oasdiff JSON)  and  --head (OpenAPI spec)
- Prompts an LLM: "You are an API security expert…" and asks for a STRICT JSON plan:
    - risks[] mapped to OWASP API Top 10
    - tests[] with method/path/persona/expectedStatus/body
- Validates model output (schema, allowed personas, reasonable size).
- Writes:
    plan.json
    generated-security-test.postman_collection.json
    llm_raw.json        # raw model response for debugging on failures

STRICT: If the LLM call fails or returns invalid JSON -> exit(1). No fallback.

Env:
  OPENAI_API_KEY  (required)
Args:
  --diff diff.json
  --head openapi/api.yaml
  --base openapi/api.v1.yaml   (optional, unused in prompt but accepted)
  --collection "security test collection"
  --plan plan.json
"""

import os, json, argparse, uuid, re, time, sys, textwrap
from pathlib import Path

# =============== OpenAI client (chat.completions) =============================

def llm_call(system, user, model="gpt-4o-mini", max_tokens=2200, temperature=0.2):
    from openai import OpenAI
    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        fail("OPENAI_API_KEY is required (LLM-only mode).")

    client = OpenAI(api_key=api_key)
    try:
        resp = client.chat.completions.create(
            model=model,
            messages=[{"role":"system","content":system},
                      {"role":"user","content":user}],
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type":"json_object"},
        )
        content = resp.choices[0].message.content
        return content
    except Exception as e:
        fail(f"LLM call failed: {e}")

# =============== Utilities =====================================================

def fail(msg: str):
    print(f"[agent] ERROR: {msg}", file=sys.stderr)
    sys.exit(1)

def read_text(path: str, limit=20000):
    try:
        s = Path(path).read_text(encoding="utf-8", errors="ignore")
        if len(s) > limit:
            head = s[: int(limit*0.6)]
            tail = s[-int(limit*0.4):]
            return head + "\n...<truncated>...\n" + tail
        return s
    except Exception:
        return ""

def load_json(path: str):
    try:
        return json.loads(Path(path).read_text())
    except Exception:
        return {}

def parse_oasdiff_paths(diff_json):
    """Extract changed/added paths from oasdiff JSON; tolerant to shapes."""
    ep = set()
    pd = diff_json.get("pathsDiff", {})
    for key in ("added", "modified"):
        vals = pd.get(key, [])
        for v in vals:
            if isinstance(v, str):
                ep.add(v)
            elif isinstance(v, dict):
                p = v.get("path")
                if p: ep.add(p)
    return sorted(ep)

def robust_json_load(s: str):
    try:
        return json.loads(s)
    except Exception:
        s2 = s.strip()
        if s2.startswith("```"):
            # strip code fences if the model added them
            s2 = re.sub(r"^```(json)?", "", s2).rstrip("`").strip()
        return json.loads(s2)

# =============== Validation ====================================================

ALLOWED_PERSONAS = {"unauth","owner","x-tenant","admin"}
ALLOWED_METHODS = {"GET","POST","PATCH","PUT","DELETE","HEAD","OPTIONS"}

def validate_plan(obj: dict):
    if not isinstance(obj, dict):
        fail("LLM output is not a JSON object.")

    # risks[]
    risks = obj.get("risks")
    if risks is None or not isinstance(risks, list):
        fail("LLM output missing 'risks' array.")
    for r in risks:
        if not isinstance(r, dict):
            fail("Each risk must be an object.")
        if "id" not in r or "severity" not in r or "explanation" not in r:
            fail("Each risk must include id, severity, explanation.")
        if not isinstance(r.get("targets", []), list):
            fail("risk.targets must be an array if present.")

    # tests[]
    tests = obj.get("tests")
    if tests is None or not isinstance(tests, list) or len(tests) == 0:
        fail("LLM output missing non-empty 'tests' array.")
    if len(tests) > 20:
        fail(f"LLM returned {len(tests)} tests (max 20). Adjust prompt/model settings.")

    for t in tests:
        if not isinstance(t, dict):
            fail("Each test must be an object.")
        for k in ("name","method","path","persona","expectedStatus"):
            if k not in t:
                fail(f"Test missing required field: {k}")
        if t["persona"] not in ALLOWED_PERSONAS:
            fail(f"Invalid persona '{t['persona']}'. Allowed: {sorted(ALLOWED_PERSONAS)}")
        if str(t["method"]).upper() not in ALLOWED_METHODS:
            fail(f"Invalid HTTP method '{t['method']}'.")
        try:
            int(t["expectedStatus"])
        except Exception:
            fail("expectedStatus must be an integer HTTP status code.")
        if "body" in t and not isinstance(t["body"], (dict, list, str, int, float, type(None))):
            fail("body must be JSON-serializable.")

    return {"risks": risks, "tests": tests}

# =============== Postman generation ===========================================

def pm_header(key, value): return {"key": key, "value": value}
def pm_script(js): return {"type": "text/javascript", "exec": js.splitlines()}

TEST_JS = r"""
function expect(code){ pm.test(pm.info.requestName, function(){ pm.response.to.have.status(code); }); }
"""

def pm_item(test):
    method = str(test["method"]).upper()
    path   = str(test["path"])
    raw = "http://127.0.0.1:8000" + path
    headers = []
    persona = test["persona"]
    if persona == "owner":
        headers.append(pm_header("Authorization", "Bearer {{t1}}"))
    elif persona == "x-tenant":
        headers.append(pm_header("Authorization", "Bearer {{t2}}"))
    elif persona == "admin":
        headers.append(pm_header("Authorization", "Bearer {{admin}}"))
    # unauth -> no header

    item = {
        "name": test["name"],
        "request": {
            "method": method,
            "header": headers,
            "url": {
                "raw": raw,
                "protocol": "http",
                "host": ["127.0.0.1"],
                "port": "8000",
                "path": [p for p in path.strip("/").split("/") if p],
            },
        },
        "event": [
            {"listen":"test","script": pm_script(TEST_JS + f"expect({int(test['expectedStatus'])});")}
        ]
    }

    if "body" in test and test["body"] is not None:
        item["request"]["header"] = item["request"].get("header", []) + [pm_header("Content-Type","application/json")]
        item["request"]["body"] = {"mode":"raw","raw": json.dumps(test["body"])}

    return item

def to_collection(name, tests):
    env_vars = {
        "t1":"t1","t2":"t2","admin":"admin",
        "userId":"1","userIdOwner":"1","userIdCross":"2",
        "accountId":"101","accountIdOwner":"101","accountIdCross":"102",
        "orderId":"201","orderIdOwner":"201","orderIdCross":"202",
    }
    items = [pm_item(t) for t in tests]
    return {
        "info":{
            "name": name,
            "_postman_id": str(uuid.uuid4()),
            "schema": "https://schema.getpostman.com/json/collection/v2.1.0/collection.json"
        },
        "item": items,
        "variable": [{"key":k,"value":v} for k,v in env_vars.items()]
    }

# =============== Prompt ========================================================

PROMPT_SYSTEM = """You are an API security expert.
Given an OpenAPI DIFF and the HEAD OpenAPI specification, analyze the changes and:
1) Identify risks mapped to OWASP API Top 10 (API1..API10). Focus on object/tenant scope, role boundaries, and authN/Z.
2) Propose HTTP tests that can confirm or refute those risks across personas.

Output STRICT JSON that matches the schema. Do not include prose or code fences. Keep tests ≤ 15.
Personas:
- unauth  : no token
- owner   : token t1 (tenant A, user 1)
- x-tenant: token t2 (tenant B, user 2)
- admin   : token admin

Status expectations (guidance, not exhaustive):
- protected route: unauth→401
- owner: 200 (for allowed actions)
- x-tenant: 403
- admin-only route for normal user: 403
"""

PROMPT_USER_TMPL = """OpenAPI DIFF:
{diff_txt}

HEAD SPEC:
{head_txt}

Output JSON schema:
{{
  "risks": [
    {{
      "id": "API1:BOLA" | "API2:BrokenAuth" | "API3:ExcessiveDataExposure" | "API4:RateLimiting" |
             "API5:BFLA" | "API6:MassAssignment" | "API7:SecurityMisconfig" | "API8:Injection" |
             "API9:ImproperInventory" | "API10:UnsafeConsumption",
      "severity": "high" | "medium" | "low",
      "explanation": "short reason",
      "targets": ["<paths impacted>"]
    }}
  ],
  "tests": [
    {{
      "name": "short test name",
      "method": "GET|POST|PATCH|PUT|DELETE",
      "path": "/users/{userId}/profile",
      "persona": "unauth" | "owner" | "x-tenant" | "admin",
      "expectedStatus": 200,
      "body": {{}}   // optional
    }}
  ]
}}
Return ONLY valid JSON.
"""

# =============== Main ==========================================================

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="openapi/api.v1.yaml")
    ap.add_argument("--head", default="openapi/api.yaml")
    ap.add_argument("--diff", default="diff.json")
    ap.add_argument("--collection", default="security test collection")
    ap.add_argument("--plan", default="plan.json")
    ap.add_argument("--model", default=os.getenv("OPENAI_MODEL","gpt-4o-mini"))
    args = ap.parse_args()

    diff_txt = read_text(args.diff)
    head_txt = read_text(args.head)

    # Call LLM
    raw = llm_call(PROMPT_SYSTEM, PROMPT_USER_TMPL.format(diff_txt=diff_txt, head_txt=head_txt), model=args.model)
    Path("llm_raw.json").write_text(raw)  # always save raw for debugging

    try:
        obj = robust_json_load(raw)
    except Exception as e:
        fail(f"Model returned non-JSON content. See llm_raw.json. Error: {e}")

    # Validate LLM output
    validated = validate_plan(obj)
    risks = validated["risks"]
    tests = validated["tests"]

    # Normalize and persist plan
    plan_out = {
        "generatedAt": int(time.time()),
        "endpointsAnalyzed": parse_oasdiff_paths(load_json(args.diff)),
        "risks": risks,
        "tests": tests,
        "personas": [
            {"id":"unauth","token":None,"description":"No token"},
            {"id":"owner","token":"t1","description":"Tenant A / User 1"},
            {"id":"x-tenant","token":"t2","description":"Tenant B / User 2"},
            {"id":"admin","token":"admin","description":"Admin"}
        ]
    }
    Path(args.plan).write_text(json.dumps(plan_out, indent=2))

    # Build Postman collection
    coll = to_collection(args.collection, tests)
    Path("generated-security-test.postman_collection.json").write_text(json.dumps(coll, indent=2))

    print("[agent] LLM plan written to plan.json; collection generated.")

if __name__ == "__main__":
    main()
