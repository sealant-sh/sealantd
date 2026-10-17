import assert from "node:assert/strict";
import { readdirSync, readFileSync } from "node:fs";
import { readFile } from "node:fs/promises";
import test from "node:test";

import { Evaluator, Lexer, Parser, data } from "@actions/expressions";
import { parse } from "yaml";

// The box's runner VMs keep state between jobs, so a workflow that publishes, or holds a token that
// writes to the repository or its packages, runs every job on a GitHub-hosted runner: a fresh VM.
// Labels are allowed, not denied: a selector such as [linux, x64] reaches the box without naming it.
const PUBLISHING = ["next.yml", "release.yml", "version.yml"];
const HOSTED = /^ubuntu-(latest|[0-9.]+(-arm)?)$/;
const MATRIX = /^\$\{\{ matrix\.[a-z.]+ \}\}$/;

/** Every runner a workflow names: runs-on values and matrix `runner:` entries, in flow or block form. */
export function runnersIn(text) {
  const lines = text.split("\n");
  const runners = [];
  lines.forEach((line, index) => {
    if (/^\s*#/.test(line)) return;
    for (const match of line.matchAll(
      /(?:runs-on|runner)"?\s*:\s*("[^"]*"|\$\{\{[^}]*\}\}|\[[^\]]*\]|[^,}#\s][^,}#]*)?/g,
    )) {
      const value = match[1]?.trim();
      if (value === undefined || value === "") {
        // A block sequence or anything else spread over lines: name the runner on one line.
        runners.push({ line: index + 1, labels: [`<multi-line value>`] });
      } else if (value.startsWith("[")) {
        const labels = value
          .slice(1, -1)
          .split(",")
          .map((label) => label.trim().replace(/^"|"$/g, ""));
        runners.push({ line: index + 1, labels });
      } else {
        runners.push({ line: index + 1, labels: [value.replace(/^"|"$/g, "")] });
      }
    }
  });
  return runners;
}

const hosted = ({ labels }) =>
  labels.length === 1 && MATRIX.test(labels[0])
    ? true
    : labels.every((label) => HOSTED.test(label));

test("workflows that publish or hold a write token run only on GitHub-hosted runners", async () => {
  for (const file of PUBLISHING) {
    const text = await readFile(
      new URL(`../.github/workflows/${file}`, import.meta.url),
      "utf8",
    );
    const runners = runnersIn(text);
    assert.ok(runners.length > 0, `${file} names its runners`);
    for (const runner of runners) {
      assert.ok(hosted(runner), `${file}:${runner.line} asks for ${runner.labels.join(", ")}`);
    }
  }
});

test("the guard refuses every way of naming a box runner", () => {
  const refused = (text) => runnersIn(text).some((runner) => !hosted(runner));
  assert.ok(refused("    runs-on: [self-hosted, box, linux, x64]\n"), "the box labels");
  assert.ok(refused("    runs-on: [linux, x64]\n"), "a selector that names no box label");
  assert.ok(refused("    runs-on: box\n"), "a scalar label");
  assert.ok(
    refused("          - { arch: amd64, runner: [self-hosted, box, linux, x64] }\n"),
    "a matrix row",
  );
  assert.ok(
    refused("          - { arch: amd64, runner: [linux, x64] }\n"),
    "a matrix row selector",
  );
  assert.ok(refused("    runs-on:\n      - linux\n      - x64\n"), "a block sequence");
  assert.ok(
    refused(`          amd64='{"arch":"amd64","runner":["linux","x64"]}'\n`),
    "JSON a step builds",
  );
  assert.ok(
    !refused("    runs-on: ubuntu-24.04\n    runs-on: ${{ matrix.platform.runner }}\n"),
    "hosted",
  );
  assert.ok(
    !refused("          - { arch: arm64, runner: ubuntu-24.04-arm }\n"),
    "a hosted matrix row",
  );
});

// x86 CI runs on GitHub-hosted runners. The box's runners stay a fallback a person picks by
// dispatching ci.yml with `runner: box`: no other event may resolve a job's runs-on to the box,
// and no event at all to a Blacksmith runner. runs-on is evaluated per event and input with
// GitHub's own expression library, as ci-concurrency.test.mjs evaluates the concurrency group.
const BOX = ["self-hosted", "box", "linux", "x64"];

const toData = (v) => {
  if (typeof v === "string") return new data.StringData(v);
  if (typeof v === "boolean") return new data.BooleanData(v);
  if (typeof v === "number") return new data.NumberData(v);
  if (v === null || v === undefined) return new data.Null();
  if (Array.isArray(v)) return new data.Array(...v.map(toData));
  const dictionary = new data.Dictionary();
  for (const [key, entry] of Object.entries(v)) dictionary.add(key, toData(entry));
  return dictionary;
};

const evaluate = (expression, context) => {
  const tree = new Parser(new Lexer(expression).lex().tokens, Object.keys(context), []).parse();
  const result = new Evaluator(tree, toData(context)).evaluate();
  return JSON.parse(JSON.stringify(result, data.replacer));
};

/** The labels a runs-on value resolves to in a context. */
const resolve = (runsOn, context) => {
  const whole = typeof runsOn === "string" && runsOn.match(/^\$\{\{(.+)\}\}$/s);
  const value = whole ? evaluate(whole[1], context) : runsOn;
  const labels = typeof value === "string" ? [value] : Array.isArray(value) ? value : value.labels;
  return [labels].flat().map((label) => {
    const inner = typeof label === "string" && label.match(/^\$\{\{(.+)\}\}$/s);
    return inner ? evaluate(inner[1], context) : label;
  });
};

/** Every matrix row a job runs, or one empty row. */
const matrixRows = (strategy) => {
  const matrix = strategy?.matrix;
  if (matrix === undefined) return [{}];
  assert.equal(typeof matrix, "object", "a matrix built by an expression is not evaluated here");
  let rows = [{}];
  for (const [key, values] of Object.entries(matrix)) {
    if (key === "include" || key === "exclude") continue;
    assert.ok(Array.isArray(values), `matrix.${key} is a literal list`);
    rows = rows.flatMap((row) => values.map((entry) => ({ ...row, [key]: entry })));
  }
  const include = matrix.include ?? [];
  return Object.keys(matrix).some((key) => key !== "include" && key !== "exclude")
    ? [...rows, ...include]
    : include;
};

/** Every (event, inputs) a workflow can run with: each dispatch choice, and every other trigger with none. */
const runsOf = (workflow) => {
  const on = workflow.on;
  const events = typeof on === "string" ? [on] : Array.isArray(on) ? on : Object.keys(on);
  return events.flatMap((event) => {
    if (event !== "workflow_dispatch") return [{ event, inputs: {} }];
    const inputs = Object.entries(on.workflow_dispatch?.inputs ?? {});
    let choices = [{}];
    for (const [name, input] of inputs) {
      const options = input.type === "choice" ? input.options : [input.default ?? ""];
      choices = choices.flatMap((chosen) => options.map((option) => ({ ...chosen, [name]: option })));
    }
    return choices.map((inputs) => ({ event, inputs }));
  });
};

const workflowFiles = readdirSync(new URL("../.github/workflows/", import.meta.url)).filter((file) =>
  /\.ya?ml$/.test(file),
);

/** Every runner every job of every workflow resolves to, per event and dispatch input. */
const resolutions = () =>
  workflowFiles.flatMap((file) => {
    const workflow = parse(readFileSync(new URL(`../.github/workflows/${file}`, import.meta.url), "utf8"));
    return runsOf(workflow).flatMap(({ event, inputs }) =>
      Object.entries(workflow.jobs).flatMap(([job, { "runs-on": runsOn, strategy }]) =>
        runsOn === undefined
          ? []
          : matrixRows(strategy).map((matrix) => ({
              file,
              event,
              inputs,
              job,
              labels: resolve(runsOn, { inputs, matrix, github: { event_name: event } }),
            })),
      ),
    );
  });

const isBox = (labels) => labels.length === BOX.length && labels.every((label, i) => label === BOX[i]);

test("only a dispatch with runner: box selects the box, and nothing selects Blacksmith", () => {
  const all = resolutions();
  assert.ok(all.some(({ event }) => event === "push"), "pushes are evaluated");
  for (const { file, event, inputs, job, labels } of all) {
    const where = `${file} ${job} on ${event} ${JSON.stringify(inputs)} -> ${JSON.stringify(labels)}`;
    assert.ok(!labels.some((label) => /blacksmith/i.test(String(label))), where);
    if (event === "workflow_dispatch" && inputs.runner === "box" && isBox(labels)) continue;
    assert.ok(hosted({ labels }), where);
  }
});

test("ci.yml runs its x86 jobs on ubuntu-24.04 and goes back to the box only when dispatched to it", () => {
  const ci = resolutions().filter(({ file }) => file === "ci.yml");
  const on = (event, job, inputs = {}) =>
    ci.find((run) => run.event === event && run.job === job && JSON.stringify(run.inputs) === JSON.stringify(inputs))
      ?.labels;
  for (const event of ["push", "pull_request"]) {
    assert.deepEqual(on(event, "rust"), ["ubuntu-24.04"]);
    assert.deepEqual(on(event, "node"), ["ubuntu-24.04"]);
    assert.deepEqual(on(event, "rust-arm64"), ["ubuntu-24.04-arm"]);
    assert.deepEqual(on(event, "changes"), ["ubuntu-24.04-arm"]);
  }
  assert.deepEqual(on("workflow_dispatch", "rust", { runner: "ubuntu-24.04" }), ["ubuntu-24.04"]);
  assert.deepEqual(on("workflow_dispatch", "rust", { runner: "box" }), BOX);
  assert.deepEqual(on("workflow_dispatch", "node", { runner: "box" }), BOX);
});
