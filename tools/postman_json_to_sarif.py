import json
import sys
import re
from pathlib import Path

def load_json(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def slugify(s: str) -> str:
    s = re.sub(r"https?://", "", s, flags=re.IGNORECASE)
    s = s.replace("127.0.0.1:8000", "")
    s = s.strip()
    s = re.sub(r"[^A-Za-z0-9/_-]+", "_", s)
    s = re.sub(r"_+", "_", s)
    s = s.strip("_/")
    if not s:
        s = "request"
    return f"postman/{s}"

def infer_level(assertion: str, message: str) -> str:
    t = f"{assertion} {message}".lower()
    if any(k in t for k in ["unauth", "401", "forbidden", "403", "authorization", "role"]):
        return "error"
    if any(k in t for k in ["bad request", "400", "validation", "conflict", "409"]):
        return "warning"
    return "note"

def rule_id_from(assertion: str) -> str:
    base = assertion or "postman_assertion"
    base = re.sub(r"[^A-Za-z0-9_-]+", "_", base)
    base = re.sub(r"_+", "_", base).strip("_")
    return f"postman.{base or 'assertion'}"

def build_sarif(run_json: dict) -> dict:
    executions = (run_json.get("run", {}).get("executions") or [])
    results = []
    rules_dict = {}

    for ex in executions:
        item_name = (ex.get("requestExecuted") or {}).get("name") or "request"
        safe_uri = slugify(item_name)

        for t in (ex.get("tests") or []):
            status = t.get("status")
            if status != "failed":
                continue
            assertion = t.get("name") or (t.get("error") or {}).get("test") or "Assertion failed"
            err = t.get("error") or {}
            message = err.get("message") or "Assertion failed"

            level = infer_level(assertion, message)
            rid = rule_id_from(assertion)

            if rid not in rules_dict:
                rules_dict[rid] = {
                    "id": rid,
                    "name": assertion[:64],
                    "shortDescription": {"text": assertion},
                    "fullDescription": {"text": assertion},
                    "help": {"text": "Postman assertion failure detected during security test run."},
                    "defaultConfiguration": {"level": level},
                }

            results.append({
                "ruleId": rid,
                "level": level,
                "message": {"text": f"{item_name}: {message}"},
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {"uri": safe_uri},
                        "region": {"startLine": 1, "startColumn": 1}
                    }
                }]
            })

    if not results:
        rid = "postman.security.cleanrun"
        rules_dict[rid] = {
            "id": rid,
            "name": "No security assertion failures",
            "shortDescription": {"text": "No security test failures"},
            "fullDescription": {"text": "Postman security tests reported zero failed assertions."},
            "help": {"text": "Review run.json for details."},
            "defaultConfiguration": {"level": "note"},
        }
        results.append({
            "ruleId": rid,
            "level": "note",
            "message": {"text": "No failed assertions were detected."},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "postman/clean_run"},
                    "region": {"startLine": 1, "startColumn": 1}
                }
            }]
        })

    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "Postman Security Test Agent",
                    "informationUri": "https://www.postman.com",
                    "rules": list(rules_dict.values())
                }
            },
            "results": results
        }]
    }
    return sarif

def main():
    if len(sys.argv) != 3:
        print("Usage: postman_json_to_sarif.py <run.json> <out.sarif.json>", file=sys.stderr)
        sys.exit(2)

    in_path = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    run_json = load_json(in_path)
    sarif = build_sarif(run_json)
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2)
    print(f"Wrote SARIF -> {out_path}")

if __name__ == "__main__":
    main()
