#!/usr/bin/env python3
import os, json, argparse, uuid, re, time, sys, textwrap
from pathlib import Path
from mcp_client import PostmanMCP

# ---------------- OpenAI ----------------
def fail(msg): print(f"[agent] ERROR: {msg}", file=sys.stderr); sys.exit(1)

def llm_call(system, user, model="gpt-4o-mini", max_tokens=2200, temperature=0.2):
    from openai import OpenAI
    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key: fail("OPENAI_API_KEY is required (LLM-only mode).")
    client = OpenAI(api_key=api_key)
    resp = client.chat.completions.create(
        model=model,
        messages=[{"role":"system","content":system},{"role":"user","content":user}],
        temperature=temperature, max_tokens=max_tokens,
        response_format={"type":"json_object"}
    )
    return resp.choices[0].message.content

def robust_json_load(s):
    try:
        return json.loads(s)
    except Exception:
        s2 = s.strip()
        if s2.startswith("```"):  # strip code fence if added
            s2 = re.sub(r"^```(json)?", "", s2).rstrip("`").strip()
        return json.loads(s2)

# ------------- I/O helpers ---------------
def read_text(path, limit=20000):
    try:
        s = Path(path).read_text(encoding="utf-8", errors="ignore")
        if len(s) > limit:
            head = s[: int(limit*0.6)]; tail = s[-int(limit*0.4):]
            return head + "\n...<truncated>...\n" + tail
        return s
    except Exception:
        return ""

def load_json(path): 
    try: return json.loads(Path(path).read_text())
    except Exception: return {}

def parse_oasdiff_paths(diff_json):
    ep = set()
    pd = diff_json.get("pathsDiff", {})
    for key in ("added","modified"):
        for v in pd.get(key, []):
            if isinstance(v, str): ep.add(v)
            elif isinstance(v, dict) and v.get("path"): ep.add(v["path"])
    return sorted(ep)

# ------------- Validation ----------------
ALLOWED_PERSONAS = {"unauth","owner","x-tenant","admin"}
ALLOWED_METHODS = {"GET","POST","PATCH","PUT","DELETE","HEAD","OPTIONS"}

def validate_plan(obj):
    if not isinstance(obj, dict): fail("LLM output is not a JSON object.")
    risks = obj.get("risks"); tests = obj.get("tests")
    if not isinstance(risks, list): fail("Missing 'risks' array.")
    if not isinstance(tests, list) or not tests: fail("Missing non-empty 'tests' array.")
    if len(tests) > 20: fail("Too many tests (>20).")
    for r in risks:
        if not isinstance(r, dict) or "id" not in r or "severity" not in r or "explanation" not in r:
            fail("Each risk must include id, severity, explanation.")
    for t in tests:
        for k in ("name","method","path","persona","expectedStatus"):
            if k not in t: fail(f"Test missing field: {k}")
        if t["persona"] not in ALLOWED_PERSONAS: fail(f"Invalid persona {t['persona']}")
        if str(t["method"]).upper() not in ALLOWED_METHODS: fail(f"Bad method {t['method']}")
        try: int(t["expectedStatus"])
        except: fail("expectedStatus must be int")
    return {"risks": risks, "tests": tests}

# ------------- Postman collection build ---
def pm_header(k,v): return {"key":k,"value":v}
def pm_script(js):  return {"type":"text/javascript","exec": js.splitlines()}
TEST_JS = "function expect(c){pm.test(pm.info.requestName,function(){pm.response.to.have.status(c);});}"

def pm_item(t):
    method = str(t["method"]).upper(); path = str(t["path"])
    raw = "http://127.0.0.1:8000" + path
    headers = []
    p = t["persona"]
    if p=="owner": headers.append(pm_header("Authorization","Bearer {{t1}}"))
    elif p=="x-tenant": headers.append(pm_header("Authorization","Bearer {{t2}}"))
    elif p=="admin": headers.append(pm_header("Authorization","Bearer {{admin}}"))
    item = {
        "name": t["name"],
        "request": {"method": method, "header": headers,
          "url":{"raw":raw,"protocol":"http","host":["127.0.0.1"],"port":"8000","path":[p for p in path.strip('/').split('/') if p]}},
        "event":[{"listen":"test","script": pm_script(TEST_JS+f"expect({int(t['expectedStatus'])});")}]
    }
    if "body" in t and t["body"] is not None:
        item["request"]["header"]=item["request"].get("header",[])+[pm_header("Content-Type","application/json")]
        item["request"]["body"]={"mode":"raw","raw": json.dumps(t["body"])}
    return item

def build_env_vars():
    return {
        "t1":"t1","t2":"t2","admin":"admin",
        "userId":"1","userIdOwner":"1","userIdCross":"2",
        "accountId":"101","accountIdOwner":"101","accountIdCross":"102",
        "orderId":"201","orderIdOwner":"201","orderIdCross":"202",
    }

def to_collection(name, tests):
    env = build_env_vars()
    return {
        "info":{"name":name,"_postman_id":str(uuid.uuid4()),
                "schema":"https://schema.getpostman.com/json/collection/v2.1.0/collection.json"},
        "item":[pm_item(t) for t in tests],
        "variable":[{"key":k,"value":v} for k,v in env.items()]
    }

# ------------- Prompts --------------------
PROMPT_SYSTEM = """You are an API security expert.
Given an OpenAPI DIFF and the HEAD OpenAPI spec, map changes to OWASP API Top 10
(API1..API10). Propose HTTP tests per persona to confirm/deny risks.
Return STRICT JSON only (no code fences), <= 15 tests."""
PROMPT_USER_TMPL = """OpenAPI DIFF:
{diff_txt}

HEAD SPEC:
{head_txt}

Output schema:
{{
  "risks": [{{"id":"API1:BOLA","severity":"high","explanation":"...","targets":["/path"]}}],
  "tests": [{{"name":"...","method":"GET|POST|PATCH|PUT|DELETE","path":"/x","persona":"unauth|owner|x-tenant|admin","expectedStatus":200,"body":{{}}}}]
}}
Personas:
- unauth: no token
- owner:  t1
- x-tenant: t2
- admin: admin
Status guidance: unauth→401; owner allowed→200; x-tenant→403; admin-only for user→403.
Return ONLY JSON.
"""

# ------------- Main -----------------------
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base", default="openapi/api.v1.yaml")
    ap.add_argument("--head", default="openapi/api.yaml")
    ap.add_argument("--diff", default="diff.json")
    ap.add_argument("--collection", default="security test collection")
    ap.add_argument("--plan", default="plan.json")
    ap.add_argument("--workspace-name", default=os.getenv("POSTMAN_WORKSPACE_NAME","Security Demo"))
    ap.add_argument("--env-name", default=os.getenv("POSTMAN_ENV_NAME","Security Demo Env"))
    ap.add_argument("--model", default=os.getenv("OPENAI_MODEL","gpt-4o-mini"))
    args = ap.parse_args()

    diff_txt = read_text(args.diff); head_txt = read_text(args.head)

    raw = llm_call(PROMPT_SYSTEM, PROMPT_USER_TMPL.format(diff_txt=diff_txt, head_txt=head_txt), model=args.model)
    Path("llm_raw.json").write_text(raw)

    obj = robust_json_load(raw)
    plan = validate_plan(obj)

    # Write normalized plan.json
    plan_out = {
        "generatedAt": int(time.time()),
        "endpointsAnalyzed": parse_oasdiff_paths(load_json(args.diff)),
        "risks": plan["risks"],
        "tests": plan["tests"],
        "personas":[
            {"id":"unauth","token":None},
            {"id":"owner","token":"t1"},
            {"id":"x-tenant","token":"t2"},
            {"id":"admin","token":"admin"},
        ]
    }
    Path(args.plan).write_text(json.dumps(plan_out, indent=2))

    # Build local collection for CLI run
    coll = to_collection(args.collection, plan_out["tests"])
    Path("generated-security-test.postman_collection.json").write_text(json.dumps(coll, indent=2))

    # -------- Push to Postman via MCP (FULL server) ----------
    # 1) resolve workspace by name
    mcp = PostmanMCP()
    ws = mcp.get_workspaces() or {}
    all_ws = ws.get("workspaces") or []
    workspace = next((w for w in all_ws if w.get("name")==args.workspace-name or w.get("name")==args.workspace_name), None)
    if not workspace:
        # Be strict: don't create workspace automatically in CI
        raise RuntimeError(f"Workspace '{args.workspace_name}' not found. Create it in Postman or change POSTMAN_WORKSPACE_NAME.")
    workspace_id = workspace["id"]

    # 2) upsert environment with tokens/ids
    mcp.upsert_environment(workspace_id, args.env_name, build_env_vars())

    # 3) create or update collection by name
    cols = mcp.get_collections(workspace_id) or {}
    existing = None
    for c in (cols.get("collections") or []):
        if c.get("name") == args.collection:
            existing = c
            break

    if existing:
        cid = existing["id"]
        mcp.update_collection(cid, coll)
        print(f"[agent] Updated collection in Postman (id={cid})")
    else:
        created = mcp.create_collection(workspace_id, coll)
        # Some tools return created collection, others only text; try to pull by name again
        cols2 = mcp.get_collections(workspace_id) or {}
        newc = next((c for c in (cols2.get("collections") or []) if c.get("name")==args.collection), None)
        print(f"[agent] Created collection in Postman (id={newc.get('id') if newc else 'unknown'})")

    print("[agent] plan.json + local+remote collection ready.")

if __name__ == "__main__":
    main()
