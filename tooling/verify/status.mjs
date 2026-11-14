// `verify status`: for each obligation the current head owes, whether a passing result exists for
// this exact commit on a clean tree. A result for another commit, or from a dirty tree, proves
// nothing about this one.
import { existsSync, readdirSync, readFileSync } from "node:fs";
import path from "node:path";

// The verb whose result discharges an obligation: its command is `pnpm verify <verb> …`.
const verbOf = (command) => command?.match(/^pnpm verify ([a-z-]+)/)?.[1];

export const readLatest = (root) => {
  const dir = path.join(root, ".verify", "latest");
  if (!existsSync(dir)) return new Map();
  return new Map(
    readdirSync(dir)
      .filter((f) => f.endsWith(".json"))
      .map((f) => [f.replace(/\.json$/, ""), JSON.parse(readFileSync(path.join(dir, f), "utf8"))]),
  );
};

export const resultPath = (result) =>
  `.verify/results/${result.verb}-${result.startedAt.replace(/[:.]/g, "-")}.json`;

// Each owed obligation, resolved against the latest results, and a step per obligation.
export const resolve = (obligations, latest, head) => {
  const steps = [];
  const resolved = obligations.map((o) => {
    const verb = verbOf(o.command);
    const result = verb ? latest.get(verb) : undefined;
    const here = result && result.head.sha === head.sha && !result.head.dirty && !head.dirty;
    let status = "owed";
    let stepStatus = o.kind === "external" ? "requires_external_observer" : "skipped";
    let detail = verb ? `no result from \`verify ${verb}\` yet` : "no verb records this yet; run the command and report it";
    if (result && !here) {
      status = "stale";
      detail = `the latest \`verify ${verb}\` result is for ${result.head.sha.slice(0, 12)}${result.head.dirty ? " with a dirty tree" : ""}`;
      if (head.dirty) detail = "the tree is dirty: commit, then run it again";
    } else if (here && result.status === "passed") {
      status = "discharged";
      stepStatus = "passed";
      detail = resultPath(result);
    } else if (here) {
      stepStatus = result.status;
      detail = `\`verify ${verb}\` ${result.status} on this commit: ${resultPath(result)}`;
    }
    steps.push({ id: o.id, title: `${o.kind}: ${o.why}`, status: stepStatus, detail, ...(o.command && { command: o.command }) });
    return { ...o, status, ...(status === "discharged" && { evidence: resultPath(result) }) };
  });
  return { obligations: resolved, steps };
};

export const markdown = (head, obligations) => {
  const lines = [`Verification for ${head.sha.slice(0, 12)}${head.dirty ? " (dirty tree)" : ""}:`, ""];
  if (obligations.length === 0) lines.push("- Nothing owed: the change touches no path in the obligations map.");
  for (const o of obligations) {
    const where = o.status === "discharged" ? `\`${o.evidence}\`` : o.command ? `run \`${o.command}\`` : o.what ?? "";
    lines.push(`- **${o.id}** (${o.kind}): ${o.status}, ${where}`);
  }
  return `${lines.join("\n")}\n`;
};
