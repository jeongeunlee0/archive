"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const ROOT = path.resolve(__dirname, "..");
const html = fs.readFileSync(path.join(ROOT, "index.html"), "utf8");
const server = fs.readFileSync(path.join(ROOT, "server.js"), "utf8");

test("inline application script has valid JavaScript syntax", () => {
  const match = html.match(/<script>([\s\S]*?)<\/script>/);
  assert.ok(match, "inline script is missing");
  assert.doesNotThrow(() => new vm.Script(match[1], { filename: "index-inline.js" }));
});

test("REA page is connected to navigation, routing and encrypted state", () => {
  for (const marker of [
    'item("#/rea", "REA 안전 분석실"',
    '[/^#\\/rea$/, () => viewRea()]',
    "reaReports: []",
    "state.reaReports.push(item)",
    'href: "#/ai/rea-explain"',
  ]) assert.ok(html.includes(marker), `missing UI marker: ${marker}`);
});

test("offline analysis includes identity, format and evidence helpers", () => {
  for (const marker of ["hashHex", "reaFormat", "reaEntropy", "reaStrings", "reaHex", "reaMarkdown"])
    assert.match(html, new RegExp(`function ${marker}|async function ${marker}`));
});

test("desktop bridge remains allowlisted, local and temporary", () => {
  assert.match(server, /const REA_TOOLS = new Set\(\["triage"[\s\S]*"har"\]\)/);
  assert.match(server, /shell: false/);
  assert.match(server, /REA_WORKSPACE: workspace/);
  assert.match(server, /fs\.mkdtempSync\(path\.join\(os\.tmpdir\(\), "rea-archive-"\)\)/);
  assert.match(server, /fs\.rmSync\(temp, \{ recursive: true, force: true \}\)/);
  assert.match(server, /if \(!REA_TOOLS\.has\(tool\)\)/);
});

test("sensitive archive files are not public", () => {
  assert.match(server, /const PUBLIC_FILES = new Set\(\["\/index\.html"\]\)/);
  assert.doesNotMatch(server, /PUBLIC_FILES[^\n]*\.env/);
});
