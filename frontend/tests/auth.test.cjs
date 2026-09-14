const assert = require("node:assert/strict");
const { readFileSync } = require("node:fs");
const path = require("node:path");
const test = require("node:test");
const vm = require("node:vm");
const ts = require("typescript");

// Transpile the actual callbacks/route and isolate only provider/HTTP adapters.
function load(relativePath, overrides = {}) {
  const filename = path.join(__dirname, "..", relativePath);
  const code = ts.transpileModule(readFileSync(filename, "utf8"), {
    compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020 },
  }).outputText;
  const exports = {};
  const context = {
    exports,
    process: { env: { NEXTAUTH_SECRET: "test-secret" } },
    require: (name) => {
      if (name === "next-auth/providers/github") return () => ({});
      if (overrides.modules?.[name]) return overrides.modules[name];
      throw new Error(`Unexpected dependency: ${name}`);
    },
    fetch: overrides.fetch ?? (() => { throw new Error("Unexpected network call"); }),
  };
  vm.runInNewContext(code, context, { filename });
  return exports;
}

test("browser session omits provider token and preserves VEXIS token", async () => {
  const { authOptions } = load("src/lib/auth.ts");
  const session = await authOptions.callbacks.session({
    session: { user: { name: "test" } },
    token: { accessToken: "FAKE_PROVIDER_SECRET", vexisToken: "FAKE_VEXIS_TOKEN" },
  });
  assert.equal(session.vexisToken, "FAKE_VEXIS_TOKEN");
  assert.equal("accessToken" in session, false);
  assert.equal(JSON.stringify(session).includes("FAKE_PROVIDER_SECRET"), false);
});

test("sign-in exchanges provider credential server-side", async () => {
  const { authOptions } = load("src/lib/auth.ts", {
    fetch: async (url, options) => {
      assert.equal(url, "http://localhost:8000/api/v1/auth/token");
      assert.equal(JSON.parse(options.body).access_token, "FAKE_PROVIDER_SECRET");
      return { ok: true, json: async () => ({ access_token: "FAKE_VEXIS_TOKEN" }) };
    },
  });
  const token = await authOptions.callbacks.jwt({ token: {}, account: { access_token: "FAKE_PROVIDER_SECRET" } });
  assert.equal(token.accessToken, "FAKE_PROVIDER_SECRET");
  assert.equal(token.vexisToken, "FAKE_VEXIS_TOKEN");
});

for (const kind of ["http", "network", "schema"]) {
  test(`sign-in fails visibly on ${kind} exchange failure`, async () => {
    const { authOptions } = load("src/lib/auth.ts", {
      fetch: async () => {
        if (kind === "network") throw new Error("FAKE_PROVIDER_SECRET");
        return { ok: kind !== "http", json: async () => ({}) };
      },
    });
    await assert.rejects(
      authOptions.callbacks.jwt({ token: {}, account: { access_token: "FAKE_PROVIDER_SECRET" } }),
      /Unable to sign in to VEXIS/,
    );
  });
}

function loadRepos(jwt, fetch) {
  return load("src/app/api/github/repos/route.ts", {
    fetch,
    modules: {
      "next-auth/jwt": { getToken: async ({ req, secret }) => {
        assert.equal(req.marker, "request");
        assert.equal(secret, "test-secret");
        return jwt;
      } },
      "next/server": { NextResponse: { json: (body, options) => ({ body, status: options?.status ?? 200 }) } },
    },
  });
}

test("repository listing uses server credential and returns only repository metadata", async () => {
  const route = loadRepos({ accessToken: "FAKE_PROVIDER_SECRET" }, async (url, options) => {
    assert.equal(options.headers.Authorization, "Bearer FAKE_PROVIDER_SECRET");
    assert.equal(options.cache, "no-store");
    return { ok: true, json: async () => [{ full_name: "test/repo", private: true, extra: "discard" }] };
  });
  const response = await route.GET({ marker: "request" });
  assert.equal(response.status, 200);
  assert.equal(response.body[0].full_name, "test/repo");
  assert.equal("extra" in response.body[0], false);
  assert.equal(JSON.stringify(response).includes("FAKE_PROVIDER_SECRET"), false);
});

test("repository listing rejects anonymous requests", async () => {
  const route = loadRepos(null);
  assert.equal((await route.GET({ marker: "request" })).status, 401);
});
