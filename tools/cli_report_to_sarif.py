#!/usr/bin/env python3
import json, sys

def guess_category(name: str, level_hint: str) -> str:
    s = (name or "").lower()
    if "unauth" in s or "401" in s:
        return "Authentication"
    if "forbidden" in s or "role" in s or "403" in s or "bfla" in s:
        return "Authorization (BFLA)"
    if "idor" in s or "object" in s or "bola" in s or "404" in s:
        return "Broken Object Level Authorization (BOLA)"
    if "invalid" in s or "400" in s or "schema" in s:
        return "Input Validation"
    if "conflict" in s or "replay" in s or "409" in s:
        return "Idempotency / Replay"
    return level_hint or "General"

def level_from_name(name: str) -> str:
    s = (name or "").lower()
    if "unauth" in s or "forbidden" in s or "role" in s or "bfla" in s:
        return "error"
    if "invalid" in s or "conflict" in s or "400" in s or "409" in s:
        return "warning"
    return "note"

def collect_failures(data):
    """Return a list of dicts: {item, test, status, message}"""
    out = []

    # 1) Top-level failures
    for f in (data.get("run", {}) or {}).get("failures", []) or data.get("failures", []) or []:
        err = f.get("error", {}) or {}
        out.append({
            "item":  f.get("source", {}).get("name") or f.get("parent", {}).get("name") or "request",
            "test":  err.get("test") or err.get("name") or err.get("message") or "Security test failed",
            "status": None,
            "message": err.get("message") or "",
        })

    # 2) Per-execution assertion failures
    for ex in (data.get("run", {}) or {}).get("executions", []) or []:
        item_name = ex.get("item", {}).get("name") or ex.get("item", {}).get("id") or "request"
        code = None
        try:
            code = ex.get("response", {}).get("code")
        except Exception:
            pass
        for a in ex.get("assertions", []) or []:
            if a.get("error"):  # failed assertion
                msg = a.get("error", {}).get("message") or a.get("message") or "Assertion failed"
                out.append({
                    "item": item_name,
                    "test": a.get("assertion") or a.get("name") or msg,
                    "status": code,
                    "message": msg,
                })
    return out

def main():
    if len(sys.argv) < 3:
        print("Usage: cli_report_to_sarif.py run.json sarif.json", file=sys.stderr)
    run_path = sys.argv[1] if len(sys.argv) > 1 else "run.json"
    out_path = sys.argv[2] if len(sys.argv) > 2 else "sarif.json"

    try:
        data = json.load(open(run_path))
    except Exception as e:
        print(f"[ERROR] cannot read {run_path}: {e}", file=sys.stderr)
        sys.exit(1)

    findings = collect_failures(data)

    # De-dupe (item + test text)
    seen = set()
    results = []
    for f in findings:
        key = (f["item"], f["test"])
        if key in seen:
            continue
        seen.add(key)

        test_name = f["test"]
        level = level_from_name(test_name)
        category = guess_category(test_name, level)

        # Build nice message
        status_note = f" (HTTP {f['status']})" if f.get("status") else ""
        msg = f"[{category}] {f['item']}: {test_name}{status_note}"

        results.append({
            "ruleId": f"postman.security.{category.replace(' ', '_').lower()}",
            "level": level,
            "message": {"text": msg},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "openapi/api.yaml"},
                    "region": {"startLine": 1}
                }
            }],
            "properties": {
                "category": category,
                "endpoint": f["item"],
                "httpStatus": f.get("status"),
            }
        })

    # Default note if all passed
    if not results:
        results.append({
            "ruleId": "postman.security.cleanrun",
            "level": "note",
            "message": {"text": "No security test failures detected"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "openapi/api.yaml"},
                    "region": {"startLine": 1}
                }
            }],
            "properties": {"category": "Info"}
        })

    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Postman Security Test Agent",
                    "rules": [{
                        "id": "postman.security",
                        "shortDescription": {"text": "API security test failure"}
                    }]
                }
            },
            "results": results
        }]
    }

    with open(out_path, "w") as f:
        json.dump(sarif, f, indent=2)
    print(f"SARIF written to {out_path} ({len(results)} results).")

if __name__ == "__main__":
    main()
