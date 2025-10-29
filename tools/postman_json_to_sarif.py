#!/usr/bin/env python3
"""
postman_json_to_sarif.py
------------------------
Convert a Postman/Newman JSON reporter file (run.json) into SARIF 2.1.0.

Usage:
  python tools/postman_json_to_sarif.py <input_run_json> <output_sarif_json>

Behavior:
- Emits one SARIF result per failed test assertion found in run["executions"][*]["tests"].
- Uses request name + test name to form a stable ruleId.
- Uses "METHOD host:port/path" as the artifact URI (pseudo file path), which renders fine in GitHub Code Scanning.
- Marks every failed assertion as level "error".

This script is dependency-free and safe to run in GitHub Actions.
"""

import json
import sys
from typing import Any, Dict, List


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def save_json(obj: Dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)


def to_uri_from_request(req: Dict[str, Any]) -> str:
    method = str(req.get("method") or "GET").upper()
    url = req.get("url") or {}

    host_parts = url.get("host") or []
    # Postman gives host as array like ["127","0","0","1"]; join with '.'
    host = ".".join(map(str, host_parts)) if host_parts else ""
    port = f":{url.get('port')}" if url.get("port") else ""
    path_parts = url.get("path") or []
    path = "/" + "/".join(map(str, path_parts)) if path_parts else "/"

    # Produce a readable pseudo-file identifier GitHub is happy to display.
    # Example: "POST 127.0.0.1:8000/orders/202/cancel"
    return f"{method} {host}{port}{path}".strip()


def to_rule_id(request_name: str, test_name: str) -> str:
    base = f"{request_name} {test_name}".lower()
    # kebab-case, limited length for safety
    import re

    rule = re.sub(r"[^a-z0-9]+", "-", base).strip("-")
    return (rule or "postman-assertion-failed")[:120]


def convert(run_json: Dict[str, Any]) -> Dict[str, Any]:
    run = run_json.get("run") or {}
    executions: List[Dict[str, Any]] = run.get("executions") or []

    rules_by_id: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for ex in executions:
        req = ex.get("requestExecuted") or ex.get("request") or {}
        req_name = req.get("name") or "(unnamed request)"
        req_uri = to_uri_from_request(req)
        http_code = (ex.get("response") or {}).get("code")

        tests = ex.get("tests") or []
        for t in tests:
            if t.get("status") != "failed":
                continue

            test_name = t.get("name") or "assertion"
            rule_id = to_rule_id(req_name, test_name)

            # Define the rule once
            if rule_id not in rules_by_id:
                rules_by_id[rule_id] = {
                    "id": rule_id,
                    "name": test_name,
                    "shortDescription": {"text": f'Failed Postman test: {test_name}'},
                    "fullDescription": {
                        "text": f'Request "{req_name}" failed test "{test_name}".'
                    },
                    "defaultConfiguration": {"level": "error"},
                    "properties": {"tags": ["postman", "security-test"]},
                }

            # Error message from Postman failure
            err = t.get("error") or {}
            msg = err.get("message") or f'Postman test "{test_name}" failed for request "{req_name}".'
            if http_code is not None:
                msg = f"{msg} (response code {http_code})"

            results.append(
                {
                    "ruleId": rule_id,
                    "level": "error",
                    "message": {"text": msg},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": req_uri},
                                "region": {"startLine": 1},
                            }
                        }
                    ],
                    "properties": {
                        "requestName": req_name,
                        "httpStatus": http_code,
                    },
                }
            )

    sarif: Dict[str, Any] = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Postman Security Test Agent",
                        "informationUri": "https://www.postman.com/",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
                "automationDetails": {"id": "postman-security-tests"},
            }
        ],
    }
    return sarif


def main(argv: List[str]) -> int:
    if len(argv) != 3:
        print(
            "Usage: python tools/postman_json_to_sarif.py <input_run_json> <output_sarif_json>",
            file=sys.stderr,
        )
        return 2

    input_path, output_path = argv[1], argv[2]
    data = load_json(input_path)
    sarif = convert(data)
    save_json(sarif, output_path)

    failed = len(sarif["runs"][0].get("results") or [])
    total_execs = len((data.get("run") or {}).get("executions") or [])
    print(
        f"Converted {failed} failed test(s) into SARIF results from {total_execs} execution(s).",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
