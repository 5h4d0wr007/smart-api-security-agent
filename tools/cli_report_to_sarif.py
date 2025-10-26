#!/usr/bin/env python3
import json, sys, re

def guess_category(name: str, level_hint: str) -> str:
    s = name.lower()
    if "unauth" in s or "401" in s:
        return "Authentication"
    if "forbidden" in s or "role" in s or "403" in s:
        return "Authorization (BFLA)"
    if "idor" in s or "object" in s or "404" in s:
        return "Broken Object Level Authorization (BOLA)"
    if "invalid" in s or "400" in s:
        return "Input Validation"
    if "conflict" in s or "409" in s:
        return "Idempotency / Replay"
    return level_hint or "General"

def level_from_name(name: str) -> str:
    s = name.lower()
    if "unauth" in s or "forbidden" in s or "role" in s:
        return "error"
    if "invalid" in s or "conflict" in s or "400" in s or "409" in s:
        return "warning"
    return "note"

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

    failures = data.get("run", {}).get("failures", []) or data.get("failures", []) or []
    results = []

    for f in failures:
        err = f.get("error", {}) or {}
        test_name = err.get("test") or err.get("message") or "Security test failed"
        item_name = f.get("source", {}).get("name") or f.get("parent", {}).get("name") or "request"
        level = level_from_name(test_name)
        category = guess_category(test_name, level)

        # Build SARIF result
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
