#!/usr/bin/env node
// `pnpm verify <verb>`: what a change owes, the pre-PR checks, and the receipt, each as one JSON
// result (TOOLKIT-SPEC.md, shared with sealant and Mend). Progress goes to stderr; with --json,
// stdout carries the result and nothing else.
import path from "node:path";
import { fileURLToPath } from "node:url";

import { check } from "./check.mjs";
import { plan } from "./plan.mjs";
import { changedFiles, git, head as readHead } from "./repo.mjs";
import { exitCode, rollUp, save, SCHEMA_VERSION } from "./result.mjs";
import { markdown, readLatest, resolve } from "./status.mjs";

const VERBS = {
  plan: "What this change owes and which CI jobs it runs [--base <ref>] [--files <paths…>]",
  check: "The pre-PR checks for what the change touches, skips reported [--all] [--base <ref>]",
  status: "Whether each obligation has a passing result for this commit [--markdown]",
  daemon: "Run a driver script against a freshly built daemon (not implemented yet)",
  formal: "Property tests and fuzz targets covering the change (not implemented yet)",
};
// Verbs other repos have. Asked for here, they say so rather than pretend.
const ELSEWHERE = ["db", "stack", "drive", "evidence", "box", "health", "runtime", "boat-harness"];

const usage = () =>
  `usage: pnpm verify <verb> [--json] [options]\n\n${Object.entries(VERBS)
    .map(([verb, line]) => `  ${verb.padEnd(8)} ${line}`)
    .join("\n")}\n`;

export const parseArgs = (argv) => {
  const args = { verb: argv[0], json: false, all: false, markdown: false, base: "origin/main", files: null };
  for (let i = 1; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") args.json = true;
    else if (a === "--all") args.all = true;
    else if (a === "--markdown") args.markdown = true;
    else if (a === "--base" && argv[i + 1] && !argv[i + 1].startsWith("--")) args.base = argv[++i];
    else if (a === "--files") {
      args.files = [];
      while (argv[i + 1] && !argv[i + 1].startsWith("--")) args.files.push(argv[++i]);
    } else throw new Error(`unknown option ${a}`);
  }
  return args;
};

const main = async () => {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const root = process.env.VERIFY_ROOT ?? git(path.resolve(here, "../.."), "rev-parse", "--show-toplevel");
  const progress = (line) => process.stderr.write(`verify: ${line}\n`);

  const argv = process.argv.slice(2);
  if (argv.length === 0 || argv[0] === "help" || argv[0] === "--help") {
    process.stderr.write(usage());
    return 0;
  }
  let args;
  try {
    args = parseArgs(argv);
    if (!VERBS[args.verb] && !ELSEWHERE.includes(args.verb)) throw new Error(`unknown verb ${args.verb}`);
  } catch (error) {
    process.stderr.write(`verify: ${error.message}\n\n${usage()}`);
    return 2;
  }

  const startedAt = new Date().toISOString();
  const started = Date.now();
  const head = readHead(root, args.base);
  let body;
  const files = () => {
    if (args.files) return args.files;
    if (!head.mergeBase) throw new Error(`no merge base with ${args.base}: fetch it, or pass --files`);
    return changedFiles(root, head.mergeBase);
  };

  try {
    if (args.verb === "plan") {
      body = plan(root, files());
    } else if (args.verb === "check") {
      const p = plan(root, files());
      const result = await check(root, { files: files(), all: args.all, progress });
      body = { ...result, ciJobs: p.ciJobs };
    } else if (args.verb === "status") {
      const p = plan(root, files());
      const { obligations, steps } = resolve(p.obligations, readLatest(root), head);
      body = {
        obligations,
        steps: steps.length ? steps : [{ id: "status", title: "Nothing owed", status: "passed" }],
        next: [...new Set(obligations.filter((o) => o.status !== "discharged" && o.command).map((o) => o.command))],
      };
      if (args.markdown && !args.json) process.stdout.write(markdown(head, obligations));
    } else {
      const what = VERBS[args.verb] ? "not built in sealantd yet" : "a verb of another Sealant repo, not sealantd";
      body = { steps: [{ id: args.verb, title: `verify ${args.verb}`, status: "not_implemented", detail: what }] };
    }
  } catch (error) {
    body = { steps: [{ id: args.verb, title: `verify ${args.verb}`, status: "failed", detail: error.message }] };
  }

  const steps = body.steps ?? [];
  const result = {
    schemaVersion: SCHEMA_VERSION,
    tool: "verify",
    repo: "sealantd",
    verb: args.verb,
    status: body.status ?? rollUp(steps.map((s) => s.status)),
    head,
    startedAt,
    durationMs: Date.now() - started,
    steps,
    obligations: body.obligations ?? [],
    evidence: body.evidence ?? [],
    cleanup: { status: "none", left: [] },
    next: body.next ?? [],
    ...(body.ciJobs && { ciJobs: body.ciJobs }),
  };
  const saved = save(root, result);

  for (const s of steps) progress(`${s.status.padEnd(9)} ${s.id}${s.detail ? `: ${s.detail}` : ""}`);
  for (const s of steps.flatMap((s) => (s.skipped ?? []).map((k) => ({ step: s.id, ...k })))) {
    progress(`  ${s.allowed ? "allowed " : "SKIPPED "} ${s.name} [${s.gate}]${s.reason ? ` ${s.reason}` : ""}`);
  }
  for (const o of result.obligations) progress(`owes ${o.id} (${o.kind}, ${o.status})${o.command ? `: ${o.command}` : ""}`);
  if (result.ciJobs) progress(`CI jobs: ${result.ciJobs.join(", ") || "none"}`);
  for (const n of result.next) progress(`next: ${n}`);
  progress(`${result.status} (${saved})`);
  if (args.json) process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  return exitCode(result.status);
};

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  process.exitCode = await main();
}
