import { test } from "node:test";
import assert from "node:assert/strict";
import { actionLabel, actionSpec, macroAddArgs, parseParams, ruleAddArgs, ruleProblems, type Action } from "./sessionHandling.ts";

test("actions turn into --action specs the CLI parses", () => {
  const cases: [Action, string][] = [
    [{ action: "check", every: 1 }, "check"],
    [{ action: "check", every: 20 }, "check:20"],
    [{ action: "run_macro", macro: "csrf", every: 0 }, "macro:csrf"],
    [{ action: "run_macro", macro: "csrf", every: 1 }, "macro:csrf:each"],
    [{ action: "run_macro", macro: "csrf", every: 5 }, "macro:csrf:5"],
    [{ action: "update", params: [] }, "update"],
    [{ action: "update", params: [["csrf", "csrf"], ["X-Token", "tok"]] }, "update:csrf,X-Token=tok"],
    [{ action: "login" }, "login"],
  ];
  for (const [a, spec] of cases) assert.equal(actionSpec(a), spec);
  assert.equal(actionLabel({ action: "run_macro", macro: "csrf", every: 1 }), "run csrf on every request");
  assert.deepEqual(parseParams(" csrf , X-Token = tok,,"), [["csrf", "csrf"], ["X-Token", "tok"]]);
});

test("macro and rule arguments keep values that start with a dash", () => {
  assert.deepEqual(
    macroAddArgs("app", " login ", [12, 15], [
      { step: 1, var: "csrf", from: "input", expr: "csrf" },
      { step: 2, var: "tok", from: "regex", expr: '-"t":"([^"]+)"' },
      { step: 2, var: " ", from: "json", expr: "ignored" },
    ]),
    ["auth", "macro", "add", "--step=12", "--step=15", "--extract=1:csrf=input:csrf", '--extract=2:tok=regex:-"t":"([^"]+)"', "--", "app", "login"],
  );
  const rule = {
    tools: ["scan", "fuzz"] as const,
    url: " https://app.test/api/ ",
    invalid: "invalid csrf",
    description: "",
    actions: [{ action: "run_macro", macro: "csrf", every: 1 }, { action: "update", params: [["csrf", "csrf"]] }] as Action[],
  };
  assert.deepEqual(ruleAddArgs("app", { ...rule, tools: [...rule.tools] }), [
    "auth", "rule", "add", "--action=macro:csrf:each", "--action=update:csrf", "--tool=scan,fuzz",
    "--url=https://app.test/api/", "--invalid=invalid csrf", "--", "app",
  ]);
  // Every tool ticked is the same as none: no --tool.
  const all = ruleAddArgs("app", { ...rule, tools: ["proxy", "send", "fuzz", "crawl", "scan", "checks"] });
  assert.ok(!all.some((a) => a.startsWith("--tool")));
});

test("a rule that can't be saved says why", () => {
  const r = { tools: [], url: "", invalid: "", description: "", actions: [] as Action[] };
  assert.deepEqual(ruleProblems(r, [], true, true), ["Add at least one action."]);
  const bad = { ...r, actions: [{ action: "check", every: 1 }, { action: "login" }, { action: "run_macro", macro: "x", every: 0 }] as Action[] };
  assert.deepEqual(ruleProblems(bad, ["csrf"], false, false), [
    "A session check needs the profile's check URL.",
    "Log in needs a profile with a login URL.",
    'No macro named "x".',
  ]);
  assert.deepEqual(ruleProblems(bad, ["x"], true, true), []);
});
