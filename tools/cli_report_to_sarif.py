import json, sys

def level_from_name(name: str) -> str:
    s = (name or "").lower()
    if "unauth" in s or "forbidden" in s or "401" in s or "403" in s: return "error"
    if "invalid" in s or "400" in s or "replay" in s or "409" in s:   return "warning"
    return "note"

def main():
    in_path  = sys.argv[1] if len(sys.argv)>1 else "run.json"
    out_path = sys.argv[2] if len(sys.argv)>2 else "sarif.json"
    data = json.load(open(in_path))
    failures = data.get("run",{}).get("failures",[]) or data.get("failures",[]) or []
    results = []
    for f in failures:
        test = (f.get("error") or {}).get("test") or (f.get("error") or {}).get("message") or "Security test failed"
        item = f.get("source",{}).get("name") or f.get("parent",{}).get("name") or "request"
        results.append({
            "ruleId": "postman.security",
            "level": level_from_name(test),
            "message": {"text": f"{item}: {test}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": "openapi/api.yaml"},
                    "region": {"startLine": 1}
                }
            }]
        })
    sarif = {
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "OpenAPI→Postman MCP Security", "rules": [
                {"id": "postman.security", "shortDescription": {"text": "Security test failure"}}
            ]}},
            "results": results
        }]
    }
    json.dump(sarif, open(out_path,"w"), indent=2)
    print(f"Wrote {out_path} with {len(results)} results.")

if __name__ == "__main__":
    main()
