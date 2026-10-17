import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

import { Evaluator, Lexer, Parser, data } from "@actions/expressions";
import { parse } from "yaml";

const workflow = parse(readFileSync(new URL("../.github/workflows/ci.yml", import.meta.url), "utf8"));

const value = (v) => {
  if (typeof v === "string") return new data.StringData(v);
  const dictionary = new data.Dictionary();
  for (const [key, entry] of Object.entries(v)) dictionary.add(key, value(entry));
  return dictionary;
};

// The concurrency group GitHub computes for a run, by GitHub's own expression library.
const group = (github) =>
  workflow.concurrency.group.replace(/\$\{\{(.+?)\}\}/g, (_, expression) => {
    const tree = new Parser(new Lexer(expression).lex().tokens, ["github"], []).parse();
    return new Evaluator(tree, value({ github: { workflow: "ci", ...github } })).evaluate().coerceString();
  });

const sha = "a".repeat(40);
const push = { event_name: "push", ref: "refs/heads/main", sha, run_id: "101" };
const pr = { event_name: "pull_request", ref: "refs/pull/7/merge", sha, run_id: "102" };
const dispatch = (run_id, ref = "refs/heads/main") => ({ event_name: "workflow_dispatch", ref, sha, run_id });

test("pushes and pull requests keep their groups", () => {
  assert.equal(workflow.concurrency["cancel-in-progress"], true);
  assert.equal(group(push), `ci-ci-${sha}`);
  assert.equal(group(pr), "ci-ci-refs/pull/7/merge");
});

test("a dispatch never shares a group with a push, a pull request or another dispatch", () => {
  const groups = [group(push), group(pr), group(dispatch("201")), group(dispatch("202", "refs/pull/7/merge"))];
  assert.equal(new Set(groups).size, groups.length, groups.join(" | "));
  assert.equal(group(dispatch("201")), "ci-ci-dispatch-201");
});
