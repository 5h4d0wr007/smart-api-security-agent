#!/usr/bin/env python3
"""
Convert Postman CLI JSON reporter output (run.json) to SARIF (sarif.json).

Usage:
  python tools/cli_report_to_sarif.py run.json sarif.json

Notes:
- Treats Postman assertion failures as SARIF "error"/"warning" findings.
- If you want only failures, set INCLUDE_PASSES = False.
- Results are attached to a virtual artifact: "postman://collection".
"""

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

INCLUDE_PASSES = False  # set True to include passed assertions as "note"

SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"

def read_json(p: str) -> Dict[str, Any]:
    try:
        return json.loads(Path(p).read_text(encoding="utf-8"))
    except Exception:
        return {}

def level_for_failure(name: str, status_code: int | None) -> str:
    """
    Heuristic severity mapping. Tweak as you like.
    - 401/403/404 mismatches often indicate authz problems: warning
    - 5xx: error
    - else: warning
    """
    if status_code is None:
        return "warning"
    if 500 <= status_code <= 599:
        return "error"
    if status_code in (401, 403, 404):
        return "warning"
    return "warning"

def short_message_for(failure: Dict[str, Any]) -> str:
    """
    Generate a compact message for the result.
    """
    msg = failure.get("error", {}).get("message") or failure.get("at") or "Assertion failed"
    return str(msg)[:300]

def extract_requests(run: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Flatten requests out of the Postman run JSON.
    Structure varies by Postman version; we read what we need defensively.
    """
    # Typical shape: run -> executions -> [{ item, request, response, assertions, ... }]
    execs = (run.get("run") or {}).get("executions") or []
    if isinstance(execs, list) and execs:
        return execs

    # Fallback older/newer variants
    return []

def request_identity(exe: Dict[str, Any]) -> Tuple[str, str]:
    """
    Return (name, url) for a single execution.
    """
    name = (exe.get("item") or {}).get("name") or "Unnamed request"
    url = ""
    req = exe.get("request") or {}
    if isinstance(req, dict):
        url = req.get("url") or ""
        if isinstance(url, dict):
            raw = url.get("raw")
            if raw:
                url = raw
            else:
                # best-effort reconstruct
                host = ".".join(url.get("host") or []) if isinstance(url.get("host"), list) else (url.get("host") or "")
                path = "/".join(url.get("path") or []) if isinstance(url.get("path"), list) else (url.get("path") or "")
                protocol = url.get("protocol") or "http"
                port = url.get("port")
                url = f"{protocol}://{host}{(':'+port) if port else ''}/{path}".rstrip("/")
        elif not isinstance(url, str):
            url = ""
    return name, url

def response_status(exe: Dict[str, Any]) -> int | None:
    res = exe.get("response") or {}
    if isinstance(res, dict):
        code = res.get("code")
        try:
            return int(code) if code is not None else None
        except Exception:
            return None
    return None

def assertion_failures(exe: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Postman puts failures in run.failures AND per-execution assertions with error objects.
    We prefer per-execution assertions for better context.
    """
    fails = []
    assertions = exe.get("assertions") or []
    for a in assertions:
        if a.get("error"):
            fails.append(a)
    return fails

def assertion_passes(exe: Dict[str, Any]) -> List[Dict[str, Any]]:
    passes = []
    assertions = exe.get("assertions") or []
    for a in assertions:
        if not a.get("error"):
            passes.append(a)
    return passes

def build_sarif(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    return {
        "version": "2.1.0",
        "$schema": SCHEMA_URI,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Postman Security Test Agent",
                        "informationUri": "postman://collection",
                        "version": "1.0.0",
                        "rules": [],  # optional — not using named rules
                    }
                },
                "results": results,
                "artifacts": [
                    {"location": {"uri": "postman://collection"}, "roles": ["analysisTarget"]}
                ],
            }
        ],
    }

def to_sarif_result(kind: str, level: str, message: str, name: str, url: str, status: int | None) -> Dict[str, Any]:
    # Map into SARIF result with a location pointing to a virtual artifact + logical region (request name)
    props = {
        "requestName": name,
        "url": url,
    }
    if status is not None:
        props["statusCode"] = status

    return {
        "ruleId": "postman.assertion",
        "kind": kind,  # "fail" or "informational"
        "level": level,  # "error" | "warning" | "note"
        "message": {"text": message},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "postman://collection"},
                    "region": {"snippet": {"text": name}},
                },
                "logicalLocations": [{"name": name, "kind": "request"}],
            }
        ],
        "properties": props,
    }

def main():
    if len(sys.argv) < 3:
        print("Usage: cli_report_to_sarif.py <run.json> <sarif.json>")
        sys.exit(2)

    run_path, out_path = sys.argv[1], sys.argv[2]
    data = read_json(run_path)
    executions = extract_requests(data)

    results: List[Dict[str, Any]] = []

    for exe in executions:
        name, url = request_identity(exe)
        status = response_status(exe)

        # Failures → SARIF errors/warnings
        for f in assertion_failures(exe):
            level = level_for_failure(f.get("assertion") or "", status)
            msg = short_message_for(f)
            results.append(to_sarif_result("fail", level, f"{name}: {msg}", name, url, status))

        # Optional: passes as notes
        if INCLUDE_PASSES:
            for p in assertion_passes(exe):
                msg = p.get("assertion") or "assertion passed"
                results.append(to_sarif_result("informational", "note", f"{name}: {msg}", name, url, status))

    # Fallback: if there were no executions (or reporter different), try run.failures
    if not executions:
        failures = (data.get("run") or {}).get("failures") or []
        for f in failures:
            at = f.get("at") or "postman"
            err = (f.get("error") or {}).get("message") or "Assertion failed"
            results.append(to_sarif_result("fail", "warning", f"{at}: {err}", at, "", None))

    sarif = build_sarif(results)
    Path(out_path).write_text(json.dumps(sarif, indent=2))
    print(f"Wrote SARIF with {len(results)} result(s) to {out_path}")

if __name__ == "__main__":
    main()
