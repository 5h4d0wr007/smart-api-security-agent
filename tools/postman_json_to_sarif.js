// tools/postman_json_to_sarif.js
// Converts Postman/Newman JSON reporter output (run.json) into SARIF 2.1.0
// Emits one SARIF "result" per failed test assertion.
//
// Usage:
//   node tools/postman_json_to_sarif.js path/to/run.json > sarif.json
//
// Notes:
// - We only emit failed tests (status === "failed").
// - ruleId is stable and deduped by request + test name.
// - locations.uri uses the HTTP method + path as a pseudo-artifact (fine for Code Scanning).
// - message.text carries the assertion error from Postman.

import fs from "node:fs";

const input = process.argv[2];
if (!input) {
  console.error("Usage: node tools/postman_json_to_sarif.js <run.json>");
  process.exit(2);
}

const raw = JSON.parse(fs.readFileSync(input, "utf8"));
const run = raw.run || {};
const executions = Array.isArray(run.executions) ? run.executions : [];

const rulesById = new Map();
const results = [];

function uriFromReq(req) {
  const method = (req?.method || "GET").toUpperCase();
  const host = (req?.url?.host || []).join(".");
  const port = req?.url?.port ? `:${req.url.port}` : "";
  const path = "/" + (req?.url?.path || []).join("/");
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
    // Build a stable ruleId: kebab-case of request + test name
    const ruleId =
      (reqName + " " + testName)
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, "-")
        .replace(/^-+|-+$/g, "")
        .slice(0, 120) || "postman-assertion-failed";

    // Register rule once
    if (!rulesById.has(ruleId)) {
      rulesById.set(ruleId, {
        id: ruleId,
        name: testName,
        shortDescription: { text: `Failed Postman test: ${testName}` },
        fullDescription: { text: `Request "${reqName}" failed test "${testName}".` },
        defaultConfiguration: { level: "error" },
        properties: {
          tags: ["postman", "security-test"],
        },
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
            artifactLocation: {
              uri: reqUri, // fine to be any string; GitHub renders it as a pseudo file path
            },
            region: { startLine: 1 }, // required by some renderers
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
  $schema: "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
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
      automationDetails: {
        id: "postman-security-tests",
      },
    },
  ],
};

console.error(
  `Converted ${results.length} failed test(s) into SARIF results from ${executions.length} execution(s).`
);
process.stdout.write(JSON.stringify(sarif, null, 2));
