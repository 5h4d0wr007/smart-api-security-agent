#[Backup Converter] added with postman_json_to_sarif (other converter) to cover different possibilities of CLI run output. E.g., Newman run
import json, sys, re
from typing import Any, Dict, List

def guess_category(name: str, level_hint: str) -> str:
    s = (name or "").lower()
    if "unauth" in s or "401" in s:
        return "Authentication"
    if "forbidden" in s or "role" in s or "403" in s:
        return "Authorization (BFLA)"
    if "idor" in s or "object" in s or "404" in s:
        return "Broken Object Level Authorization (BOLA)" #BOLA/BOPLA/BFLA can be a group of 403/404
    if "invalid" in s or "400" in s:
        return "Input Validation"
    if "conflict" in s or "409" in s:
        return "Idempotency / Replay"
    return level_hint or "General"

def level_from_name(name: str) -> str:
    s = (name or "").lower()
    if "unauth" in s or "forbidden" in s or "role" in s:
        return "error"
    if "invalid" in s or "conflict" in s or "400" in s or "409" in s:
        return "warning"
    return "note"

def _safe_get(d: Dict[str, Any], path: List[str], default=None):
    cur = d
    for p in path:
        if not isinstance(cur, dict) or p not in cur:
            return default
        cur = cur[p]
    return cur

def _collect_failures_from_executions(run_obj: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    executions = run_obj.get("executions") or []
    if not isinstance(executions, list):
        return out

    for ex in executions:
        item_name = (
            _safe_get(ex, ["item", "name"]) or
            _safe_get(ex, ["request", "name"]) or
            ex.get("itemName") or
            ex.get("cursor", {}).get("iterationData", {}).get("name") or
            "request"
        )
        assertions = ex.get("assertions") or []
        if not isinstance(assertions, list):
            continue
        for a in assertions:
            err = a.get("error")
            if not err:
                continue 
            test_name = a.get("assertion") or a.get("name") or err.get("name") or err.get("message") or "Security test failed"
            out.append({
                "error": {
                    "test": test_name,
                    "message": err.get("message") or test_name
                },
                "source": {
                    "name": item_name
                }
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

    failures = (
        _safe_get(data, ["run", "failures"], []) or
        data.get("failures", []) or
        _collect_failures_from_executions(_safe_get(data, ["run"], {}) or {})
    )

    results: List[Dict[str, Any]] = []

    for f in failures:
        err = f.get("error", {}) or {}
        test_name = err.get("test") or err.get("message") or "Security test failed"
        item_name = (
            _safe_get(f, ["source", "name"]) or
            _safe_get(f, ["parent", "name"]) or
            f.get("itemName") or
            "request"
        )

        level = level_from_name(test_name)
        category = guess_category(test_name, level)

        results.append({
            "ruleId": f"postman.security.{category.replace(' ', '_').lower()}",
            "level": level,
            "message": {"text": f"[{category}] {item_name}: {test_name}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "openapi/api.yaml"},
                    "region": {"startLine": 1}
                }
            }],
            "properties": {"category": category, "endpoint": item_name}
        })

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
