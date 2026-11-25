import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import test from "node:test";
import { Script } from "node:vm";

const html = readFileSync(new URL("../skills/dashboard.html", import.meta.url), "utf8").replace(/\r\n?/g, "\n");

test("the content security policy authorizes the shipped dashboard script", () => {
  const scripts = [...html.matchAll(/<script>([\s\S]*?)<\/script>/gi)];
  assert.equal(scripts.length, 1);
  const script = scripts[0][1];
  new Script(script);
  const hash = createHash("sha256").update(script).digest("base64");
  const policy = html.match(/<meta http-equiv="Content-Security-Policy" content="([^"]+)"/i)?.[1];
  assert.ok(policy);
  assert.equal(policy.split(";").find((rule) => rule.trim().startsWith("script-src"))?.trim(), `script-src 'sha256-${hash}'`);
});

test("memory markup and task templates avoid inline event attributes", () => {
  assert.doesNotMatch(html, /<[a-z][^<>]*\son(?:click|input|change|load|error|dragstart)\s*=/i);
  assert.match(html, /title\.textContent\s*=\s*task\.title/);
  assert.match(html, /note\.textContent\s*=\s*task\.note/);
  assert.match(html, /subtaskText\.textContent\s*=\s*subtask\.text/);
});
