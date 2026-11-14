// `verify plan`: what a change owes, from the obligations map, and which CI jobs it runs. CI's own
// scoping script decides both "is this documentation only" and therefore "does it owe the pre-PR
// checks", so the local answer and the PR's cannot disagree.
import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

import { parse } from "yaml";

import { matchesAny } from "./repo.mjs";

const here = path.dirname(fileURLToPath(import.meta.url));

export const loadMap = (file = path.join(here, "obligations.json")) => JSON.parse(readFileSync(file, "utf8"));

// Runs CI's scoping script (an entry's `from`) on `files`, as a pull request would. True when the
// change is code, false when CI would call it documentation only.
export const ciSaysCode = (root, script, files) => {
  const result = spawnSync("bash", [path.join(root, script)], {
    cwd: root,
    encoding: "utf8",
    env: { ...process.env, EVENT: "pull_request", FILES: files.join("\n") },
  });
  if (result.status !== 0) throw new Error(`${script} failed: ${result.stderr}`);
  const out = result.stdout.trim();
  if (out !== "code=true" && out !== "code=false") throw new Error(`${script} printed ${out}`);
  return out === "code=true";
};

// The jobs ci.yml runs on a pull request: all of them for code, and only those whose `if` does not
// read the scoping job's `code` output for documentation.
export const ciJobs = (root, code) => {
  const workflow = parse(readFileSync(path.join(root, ".github/workflows/ci.yml"), "utf8"));
  return Object.entries(workflow.jobs)
    .filter(([, job]) => code || !String(job.if ?? "").includes("outputs.code"))
    .map(([id]) => id);
};

// The obligations `files` owe, each with `"status": "owed"`. An entry owes when any file matches
// its `paths`, or, for an entry read `from` CI's scoping script, when that script calls it code.
export const obligationsFor = (root, map, files) => {
  const owed = [];
  for (const entry of map) {
    const hit = entry.from
      ? files.length > 0 && ciSaysCode(root, entry.from, files)
      : files.some((f) => matchesAny(f, entry.paths));
    if (!hit) continue;
    const matched = entry.from ? files : files.filter((f) => matchesAny(f, entry.paths));
    for (const owe of entry.owes) {
      owed.push({
        id: entry.owes.length > 1 ? `${entry.id}:${owe.kind}` : entry.id,
        kind: owe.kind,
        why: entry.why,
        status: "owed",
        ...(owe.command && { command: owe.command }),
        ...(owe.model && { model: owe.model }),
        ...(owe.what && { what: owe.what }),
        ...(owe.note && { note: owe.note }),
        paths: matched,
      });
    }
  }
  return owed;
};

export const plan = (root, files, map = loadMap()) => {
  const code = files.length > 0 && ciSaysCode(root, "scripts/ci-docs-only.sh", files);
  const obligations = obligationsFor(root, map, files);
  return {
    status: "passed",
    obligations,
    ciJobs: files.length > 0 ? ciJobs(root, code) : [],
    steps: [
      {
        id: "plan",
        title: "Match the change against the obligations map",
        status: "passed",
        detail: `${files.length} changed file(s), ${obligations.length} obligation(s), CI ${code ? "runs every job" : "runs only the scoping job"}`,
      },
    ],
    next: [...new Set(obligations.map((o) => o.command).filter(Boolean))],
  };
};
