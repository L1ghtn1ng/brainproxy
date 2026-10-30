import { test } from "node:test";
import assert from "node:assert/strict";
import { EMPTY_CERT, EMPTY_UPSTREAM, certAddArgs, hostsAddArgs, passthroughAddArgs, platformArgs, platformForm, upstreamAddArgs } from "./connection.ts";

test("upstream rules: a proxy with credentials from a variable, or direct", () => {
  assert.deepEqual(
    upstreamAddArgs({ ...EMPTY_UPSTREAM, host: " *.corp.test ", proxy: "socks5://127.0.0.1:1080", username: "u", passwordEnv: "PW", first: true }),
    ["connection", "upstream", "add", "--host=*.corp.test", "--proxy=socks5://127.0.0.1:1080", "--username=u", "--password-env=PW", "--first"],
  );
  // Direct rules carry no proxy or credentials; a variable without a user isn't sent.
  assert.deepEqual(upstreamAddArgs({ ...EMPTY_UPSTREAM, host: "intranet.test", direct: true, username: "u" }), [
    "connection",
    "upstream",
    "add",
    "--host=intranet.test",
    "--direct",
  ]);
  assert.deepEqual(upstreamAddArgs({ ...EMPTY_UPSTREAM, proxy: "http://127.0.0.1:3128", passwordEnv: "PW" }).slice(4), ["--proxy=http://127.0.0.1:3128"]);
});

test("client certificates: PEM pair or PKCS#12 with its password variable", () => {
  assert.deepEqual(certAddArgs({ ...EMPTY_CERT, host: "api.test", cert: "/c.pem", key: "/k.pem", passwordEnv: "X" }), [
    "connection",
    "cert",
    "add",
    "--host=api.test",
    "--cert=/c.pem",
    "--key=/k.pem",
  ]);
  assert.deepEqual(certAddArgs({ ...EMPTY_CERT, host: "*", kind: "pkcs12", pkcs12: "/id.p12", passwordEnv: "P12_PW" }).slice(4), [
    "--pkcs12=/id.p12",
    "--password-env=P12_PW",
  ]);
});

test("hosts and pass-through take values that may start with a dash", () => {
  assert.deepEqual(hostsAddArgs(" app.test ", "10.0.0.5"), ["connection", "hosts", "add", "--", "app.test", "10.0.0.5"]);
  assert.deepEqual(passthroughAddArgs("bank.test, *.pinned.test\n-odd.test"), [
    "connection",
    "passthrough",
    "add",
    "--",
    "bank.test",
    "*.pinned.test",
    "-odd.test",
  ]);
});

test("platform auth flags round-trip through the form", () => {
  assert.deepEqual(platformArgs(platformForm()), []);
  const f = platformForm({ scheme: "ntlm", hosts: ["*.corp.test", "intranet:8080"], domain: "CORP" });
  assert.deepEqual(platformArgs(f), ["--platform=ntlm", "--platform-host=*.corp.test", "--platform-host=intranet:8080", "--domain=CORP"]);
  // The domain is for NTLM only.
  assert.deepEqual(platformArgs({ ...f, scheme: "digest" }), ["--platform=digest", "--platform-host=*.corp.test", "--platform-host=intranet:8080"]);
});
