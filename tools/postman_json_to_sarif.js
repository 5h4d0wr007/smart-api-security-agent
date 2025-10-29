// tools/postman_json_to_sarif.js
// Convert Postman/Newman JSON reporter output (run.json) into SARIF 2.1.0
// One SARIF "result" per failed test assertion.
//
// Usage:
//   node tools/postman_json_to_sarif.js artifacts/run.json > artifacts/sarif.json
//
// This script is intentionally dependency-free (Node >= 16).

import fs from "node:fs";

function exitWithUsage() {
  console.error("Usage: node tools/postman_json_to_sarif.js <run.json>");
  process.exit(2);
}

const input = process.argv[2];
if (!input) exitWithUsage();

let rawJson;
try {
  rawJson = fs.readFileSync(input, "utf8");
} catch (e) {
  console.error(`Cannot read ${input}: ${e.message}`);
  process.exit(2);
}

let parsed;
try {
  parsed = JSON.parse(rawJson);
} catch (e) {
  console.error(`Invalid JSON in ${input}: ${e.message}`);
  process.exit(2);
}

const run = parsed.run || {};
const executions = Array.isArray(run.executions) ? run.executions : [];

const rulesById = new Map();
const results = [];

function joinSafe(arr, sep) {
  return Array.isArray(arr) ? arr.join(sep) : "";
}

function uriFromReq(req) {
  const method = (req?.method || "GET").toUpperCase();
  const host = joinSafe(req?.url?.host, ".") || "localhost";
  const port = req?.url?.port ? `:${req.url.port}` : "";
  const path = "/" + joinSafe(req?.url?.path, "/");
  return `${method} ${host}${port}${path}`;
}

for (const ex of executions) {
  const req = ex.requestExecuted || ex.request || {};
  const reqName = req.name || "(unnamed request)";
  const reqUri = uriFromReq(req);
  const httpCode = ex.response?.code;

  const tests = Array.isArray(ex.tests) ? ex.tests : [];
  for (const t of tests) {
    if (t.status !== "failed") continue;

    const testName = t.name || "assertion";

    // Create a stable, deduped ruleId based on request + test name
    const ruleId =
      (reqName + " " + testName)
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 120) || "postman-assertion-failed";

    if (!rulesById.has(ruleId)) {
      rulesById.set(ruleId, {
        id: ruleId,
        name: testName,
        shortDescription: { text: `Failed Postman test: ${testName}` },
        fullDescription: { text: `Request "${reqName}" failed test "${testName}".` },
        defaultConfiguration: { level: "error" },
        properties: { tags: ["postman", "security-test"] },
      });
    }

    const messageText =
      t.error?.message
        ? `${t.error.message}${httpCode ? ` (response code ${httpCode})` : ""}`
        : `Postman test "${testName}" failed for request "${reqName}".`;

    results.push({
      ruleId,
      level: "error",
      message: { text: messageText },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: reqUri },
            region: { startLine: 1 },
          },
        },
      ],
      properties: {
        requestName: reqName,
        httpStatus: httpCode,
      },
    });
  }
}

const sarif = {
  $schema:
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  version: "2.1.0",
  runs: [
    {
      tool: {
        driver: {
          name: "Postman Security Test Agent",
          informationUri: "https://www.postman.com/",
          rules: Array.from(rulesById.values()),
        },
      },
      results,
      automationDetails: { id: "postman-security-tests" },
    },
  ],
};

console.error(
  `Converted ${results.length} failed test(s) into SARIF results from ${executions.length} execution(s).`
);
process.stdout.write(JSON.stringify(sarif, null, 2));
