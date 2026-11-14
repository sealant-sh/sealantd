// The one result every verb prints (TOOLKIT-SPEC.md, shared with sealant and Mend). This file is
// the schema's single home: `validate` is what the tests hold every verb's output to.
import { copyFileSync, mkdirSync, writeFileSync } from "node:fs";
import path from "node:path";

export const SCHEMA_VERSION = 1;

// Worst first: a verb's status is the first of these any step has.
export const STATUSES = [
  "failed",
  "blocked_by_prerequisite",
  "skipped",
  "not_implemented",
  "requires_external_observer",
  "evidence_withheld",
  "passed",
];

// Exit codes: 0 passed, 1 failed, 2 wrong usage (verify.mjs), 3 blocked_by_prerequisite, 4 the rest.
export const exitCode = (status) =>
  status === "passed" ? 0 : status === "failed" ? 1 : status === "blocked_by_prerequisite" ? 3 : 4;

export const rollUp = (statuses) => {
  let worst = STATUSES.length - 1;
  for (const status of statuses) worst = Math.min(worst, STATUSES.indexOf(status));
  return STATUSES[worst];
};

const KINDS = ["tests", "formal", "stack", "screenshots", "box-check", "harness", "external"];

// Returns the problems with `result`, empty when it matches the schema. Optional fields this repo
// adds (`ciJobs`, an obligation's `note`) are checked when present.
export const validate = (result) => {
  const errors = [];
  const need = (ok, what) => ok || errors.push(what);
  const isString = (v) => typeof v === "string";
  const isMs = (v) => Number.isInteger(v) && v >= 0;
  const isStatus = (v) => STATUSES.includes(v);
  need(result && typeof result === "object", "result is not an object");
  if (!result || typeof result !== "object") return errors;
  need(result.schemaVersion === SCHEMA_VERSION, "schemaVersion");
  need(result.tool === "verify", "tool");
  need(result.repo === "sealantd", "repo");
  need(isString(result.verb), "verb");
  need(isStatus(result.status), `status ${result.status}`);
  const head = result.head ?? {};
  need(isString(head.sha) && /^[0-9a-f]{40}$/.test(head.sha), "head.sha");
  need(isString(head.branch), "head.branch");
  need(typeof head.dirty === "boolean", "head.dirty");
  need(isString(head.base), "head.base");
  need(head.mergeBase === null || /^[0-9a-f]{40}$/.test(head.mergeBase ?? ""), "head.mergeBase");
  need(isString(result.startedAt) && !Number.isNaN(Date.parse(result.startedAt)), "startedAt");
  need(isMs(result.durationMs), "durationMs");
  need(Array.isArray(result.steps), "steps");
  for (const [i, step] of (result.steps ?? []).entries()) {
    need(isString(step.id) && isString(step.title), `steps[${i}] id/title`);
    need(isStatus(step.status), `steps[${i}].status`);
    need(step.command === undefined || isString(step.command), `steps[${i}].command`);
    need(step.durationMs === undefined || isMs(step.durationMs), `steps[${i}].durationMs`);
    need(step.log === undefined || isString(step.log), `steps[${i}].log`);
    need(step.detail === undefined || isString(step.detail), `steps[${i}].detail`);
    for (const skip of step.skipped ?? []) {
      need(isString(skip.name) && isString(skip.gate), `steps[${i}].skipped entry`);
    }
  }
  need(Array.isArray(result.obligations), "obligations");
  for (const [i, o] of (result.obligations ?? []).entries()) {
    need(isString(o.id) && isString(o.why), `obligations[${i}] id/why`);
    need(KINDS.includes(o.kind), `obligations[${i}].kind ${o.kind}`);
    need(["owed", "discharged", "stale"].includes(o.status), `obligations[${i}].status`);
    need(o.command === undefined || isString(o.command), `obligations[${i}].command`);
  }
  need(Array.isArray(result.evidence), "evidence");
  for (const e of result.evidence ?? []) need(isString(e.kind) && isString(e.path), "evidence entry");
  need(["clean", "left", "none"].includes(result.cleanup?.status), "cleanup.status");
  need(Array.isArray(result.cleanup?.left), "cleanup.left");
  need(Array.isArray(result.next) && result.next.every(isString), "next");
  need(result.ciJobs === undefined || (Array.isArray(result.ciJobs) && result.ciJobs.every(isString)), "ciJobs");
  return errors;
};

// Writes `.verify/results/<verb>-<UTC timestamp>.json` and copies it to `.verify/latest/<verb>.json`.
export const save = (root, result) => {
  const stamp = result.startedAt.replace(/[:.]/g, "-");
  const results = path.join(root, ".verify", "results");
  const latest = path.join(root, ".verify", "latest");
  mkdirSync(results, { recursive: true });
  mkdirSync(latest, { recursive: true });
  const file = path.join(results, `${result.verb}-${stamp}.json`);
  writeFileSync(file, `${JSON.stringify(result, null, 2)}\n`);
  copyFileSync(file, path.join(latest, `${result.verb}.json`));
  return path.relative(root, file);
};
