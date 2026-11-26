import fs from "node:fs";
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { inventory } from "../src/inventory.js";
import {
  HttpError,
  extractFixedVersion,
  normalizePackageName,
  parseCvssV3,
  parseGoMod,
  parsePackageLock,
  parsePackagesLock,
  parsePnpmLock,
  parsePoetryLock,
  parsePomXml,
  parseRequirements,
  runSca,
  type HttpClient,
} from "../src/sca.js";
import { FIXTURES, cleanup, makeTempDir, writeFile } from "./helpers.js";

const temp = makeTempDir("sca");

afterAll(() => cleanup(temp));

describe("lockfile parsers", () => {
  it("parses package-lock.json v3", () => {
    const content = JSON.stringify({
      lockfileVersion: 3,
      packages: {
        "": { name: "app", version: "1.0.0" },
        "node_modules/lodash": { version: "4.17.15" },
        "node_modules/@scope/pkg": { version: "1.2.3" },
      },
    });
    const parsed = parsePackageLock(content, "package-lock.json");
    expect(parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}`)).toEqual([
      "lodash@4.17.15",
      "@scope/pkg@1.2.3",
    ]);
  });

  it("parses pnpm-lock.yaml (v9 keys and scoped packages)", () => {
    const content = [
      "lockfileVersion: '9.0'",
      "packages:",
      "  lodash@4.17.15:",
      "    resolution: {integrity: sha512-fake}",
      "  '@scope/pkg@1.2.3':",
      "    resolution: {integrity: sha512-fake}",
      "",
    ].join("\n");
    const parsed = parsePnpmLock(content, "pnpm-lock.yaml");
    expect(parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}`)).toEqual([
      "lodash@4.17.15",
      "@scope/pkg@1.2.3",
    ]);
  });

  it("parses only == pinned requirements", () => {
    const content = "Django==3.2.0\nrequests>=2.0\nflask==2.2.5 # pinned\n";
    const parsed = parseRequirements(content, "requirements.txt");
    expect(parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}`)).toEqual([
      "Django@3.2.0",
      "flask@2.2.5",
    ]);
    expect(parsed.warnings[0]).toContain("unresolved transitive dependencies");
  });

  it("parses poetry.lock blocks", () => {
    const content = [
      "[[package]]",
      'name = "django"',
      'version = "3.2.0"',
      "",
      "[[package]]",
      'name = "requests"',
      'version = "2.19.0"',
      "",
    ].join("\n");
    const parsed = parsePoetryLock(content, "poetry.lock");
    expect(parsed.packages).toHaveLength(2);
    expect(parsed.packages[0]).toMatchObject({
      name: "django",
      version: "3.2.0",
      ecosystem: "PyPI",
    });
  });

  it("parses go.mod require blocks", () => {
    const content = [
      "module example.com/app",
      "",
      "require (",
      "\tgithub.com/gin-gonic/gin v1.7.0",
      "\tgolang.org/x/text v0.3.5 // indirect",
      ")",
      "",
      "require github.com/pkg/errors v0.9.1",
      "",
    ].join("\n");
    const parsed = parseGoMod(content, "go.mod");
    expect(parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}`)).toEqual([
      "github.com/gin-gonic/gin@v1.7.0",
      "golang.org/x/text@v0.3.5",
      "github.com/pkg/errors@v0.9.1",
    ]);
    expect(parsed.packages[1]?.direct).toBe(false);
  });

  it("parses literal-version direct Maven dependencies only", () => {
    const content = [
      "<project>",
      "  <dependencyManagement><dependencies>",
      "    <dependency><groupId>managed</groupId><artifactId>lib</artifactId><version>9.9.9</version></dependency>",
      "  </dependencies></dependencyManagement>",
      "  <dependencies>",
      "    <dependency><groupId>org.example</groupId><artifactId>app</artifactId><version>1.2.3</version></dependency>",
      "    <dependency><groupId>org.example</groupId><artifactId>prop</artifactId><version>${prop.version}</version></dependency>",
      "  </dependencies>",
      "</project>",
      "",
    ].join("\n");
    const parsed = parsePomXml(content, "pom.xml");
    expect(parsed.packages.map((pkg) => `${pkg.name}@${pkg.version}`)).toEqual([
      "org.example:app@1.2.3",
    ]);
    expect(parsed.warnings[0]).toContain("unresolved transitive dependencies");
  });

  it("parses packages.lock.json for NuGet", () => {
    const content = JSON.stringify({
      version: 1,
      dependencies: {
        "net8.0": {
          "Newtonsoft.Json": {
            type: "Direct",
            resolved: "12.0.1",
          },
        },
      },
    });
    const parsed = parsePackagesLock(content, "packages.lock.json");
    expect(parsed.packages[0]).toMatchObject({
      name: "Newtonsoft.Json",
      version: "12.0.1",
      ecosystem: "NuGet",
    });
  });

  it("computes CVSS v3 base scores", () => {
    expect(
      parseCvssV3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"),
    ).toBeCloseTo(9.8, 1);
    expect(
      parseCvssV3("CVSS:3.1/AV:N/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"),
    ).toBeLessThan(4);
  });
});

function makeProject(): { root: string; packages: string } {
  const root = path.join(temp, "project");
  const packages = JSON.stringify({
    lockfileVersion: 3,
    packages: {
      "": { name: "app", version: "1.0.0" },
      "node_modules/lodash": { version: "4.17.15" },
      "node_modules/minimist": { version: "1.2.5" },
    },
  });
  writeFile(root, "package-lock.json", packages);
  return { root, packages };
}

function makeMockClient(counters: { post: number; get: number }): HttpClient {
  return {
    async postJson(_url, body) {
      counters.post += 1;
      const queries = (body as { queries: unknown[] }).queries;
      return {
        results: queries.map(() => ({ vulns: [{ id: "GHSA-test-0001" }] })),
      };
    },
    async getJson(url) {
      counters.get += 1;
      expect(url).toContain("GHSA-test-0001");
      return {
        id: "GHSA-test-0001",
        summary: "Prototype pollution in test package",
        aliases: ["CVE-2020-0001"],
        severity: [
          {
            type: "CVSS_V3",
            score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
          },
        ],
        affected: [
          {
            ranges: [{ events: [{ fixed: "4.17.19" }] }],
          },
        ],
        database_specific: { cwe_ids: ["CWE-1321"] },
      };
    },
  };
}

describe("OSV SCA orchestration", () => {
  it("batches queries, fetches details and builds findings", async () => {
    const { root } = makeProject();
    const counters = { post: 0, get: 0 };
    const result = await runSca({
      root,
      inventory: inventory(root),
      http: makeMockClient(counters),
      batchSize: 1,
    });

    expect(result.packages).toHaveLength(2);
    expect(counters.post).toBe(2);
    expect(counters.get).toBe(1);
    expect(result.findings).toHaveLength(2);
    for (const finding of result.findings) {
      expect(finding.category).toBe("sca");
      expect(finding.severity).toBe("critical");
      expect(finding.cvss).toBeCloseTo(9.8, 1);
      expect(finding.fixedVersion).toBe("4.17.19");
      expect(finding.advisoryId).toBe("GHSA-test-0001");
      expect(finding.aliases).toContain("CVE-2020-0001");
      expect(finding.reachable).toBe("unknown");
    }
  });

  it("degrades to a warning when the OSV query fails", async () => {
    const { root } = makeProject();
    const client: HttpClient = {
      async postJson() {
        throw new Error("network down");
      },
      async getJson() {
        throw new Error("should not be called");
      },
    };
    const result = await runSca({
      root,
      inventory: inventory(root),
      http: client,
    });
    expect(result.findings).toHaveLength(0);
    expect(result.warnings.join("\n")).toContain("OSV batch query failed");
    expect(result.degraded).toBe(true);
  });

  it("keeps status ok when inputs are unresolved but queries succeed", async () => {
    const root = path.join(temp, "unresolved-ok");
    writeFile(
      root,
      "package-lock.json",
      JSON.stringify({
        lockfileVersion: 3,
        packages: {
          "": { name: "app", version: "1.0.0" },
          "node_modules/lodash": { version: "4.17.15" },
        },
      }),
    );
    writeFile(root, "requirements.txt", "Django==3.2.0\nrequests>=2.0\n");
    const result = await runSca({
      root,
      inventory: inventory(root),
      http: makeMockClient({ post: 0, get: 0 }),
    });
    expect(result.warnings.join("\n")).toContain("unresolved transitive dependencies");
    expect(result.unresolvedManifests.length).toBeGreaterThan(0);
    expect(result.degraded).toBe(false);
  });

  it("normalizes PyPI names in OSV query payloads", async () => {
    const root = path.join(temp, "pypi-normalize");
    writeFile(root, "requirements.txt", "Django==3.2.0\nFlask_Login==0.6.1\n");
    const sent: string[] = [];
    const client: HttpClient = {
      async postJson(_url, body) {
        for (const query of (body as { queries: Array<{ package: { name: string } }> })
          .queries) {
          sent.push(query.package.name);
        }
        return { results: (body as { queries: unknown[] }).queries.map(() => ({})) };
      },
      async getJson() {
        throw new Error("should not be called");
      },
    };
    await runSca({ root, inventory: inventory(root), http: client });
    expect(sent.sort()).toEqual(["django", "flask-login"]);
  });

  it("skips network access entirely in offline mode", async () => {
    const { root } = makeProject();
    const counters = { post: 0, get: 0 };
    const result = await runSca({
      root,
      inventory: inventory(root),
      http: makeMockClient(counters),
      offline: true,
    });
    expect(counters).toEqual({ post: 0, get: 0 });
    expect(result.packages).toHaveLength(2);
    expect(result.findings).toHaveLength(0);
    expect(result.warnings.join("\n")).toContain("offline mode");
  });
});

describe("fixed version selection", () => {
  it("picks the smallest fixed version above the installed version", () => {
    const detail = {
      affected: [
        {
          package: { name: "lodash", ecosystem: "npm" },
          ranges: [{ events: [{ fixed: "4.17.21" }] }],
        },
        {
          package: { name: "lodash", ecosystem: "npm" },
          ranges: [
            { events: [{ last_affected: "4.17.18" }] },
            { events: [{ fixed: "4.17.20" }] },
            { events: [{ fixed: "4.17.19" }] },
          ],
        },
        {
          package: { name: "other", ecosystem: "npm" },
          ranges: [{ events: [{ fixed: "1.0.0" }] }],
        },
      ],
    };
    expect(
      extractFixedVersion(detail, {
        name: "lodash",
        version: "4.17.15",
        ecosystem: "npm",
      }),
    ).toBe("4.17.19");
  });

  it("returns undefined when the advisory only has last_affected", () => {
    const detail = {
      affected: [
        {
          package: { name: "lodash", ecosystem: "npm" },
          ranges: [{ events: [{ last_affected: "4.17.15" }] }],
        },
      ],
    };
    expect(
      extractFixedVersion(detail, {
        name: "lodash",
        version: "4.17.15",
        ecosystem: "npm",
      }),
    ).toBeUndefined();
  });

  it("ignores fixed versions that do not upgrade the installed version", () => {
    const detail = {
      affected: [{ ranges: [{ events: [{ fixed: "4.17.15" }] }] }],
    };
    expect(
      extractFixedVersion(detail, { name: "lodash", version: "4.17.15" }),
    ).toBeUndefined();
  });

  it("normalizes package names per ecosystem", () => {
    expect(normalizePackageName("Django", "PyPI")).toBe("django");
    expect(normalizePackageName("Flask_Login", "PyPI")).toBe("flask-login");
    expect(normalizePackageName("zope.interface", "PyPI")).toBe("zope-interface");
    expect(normalizePackageName("My-Pkg", "npm")).toBe("My-Pkg");
    expect(normalizePackageName("github.com/Foo/Bar", "Go")).toBe(
      "github.com/Foo/Bar",
    );
    expect(normalizePackageName("Newtonsoft.Json", "NuGet")).toBe(
      "newtonsoft.json",
    );
  });

  it("matches PyPI advisories case- and separator-insensitively", () => {
    const detail = {
      affected: [
        {
          package: { name: "django", ecosystem: "PyPI" },
          ranges: [{ events: [{ fixed: "3.2.25" }] }],
        },
        {
          package: { name: "flask-login", ecosystem: "PyPI" },
          ranges: [{ events: [{ fixed: "0.6.3" }] }],
        },
      ],
    };
    expect(
      extractFixedVersion(detail, {
        name: "Django",
        version: "3.2.0",
        ecosystem: "PyPI",
      }),
    ).toBe("3.2.25");
    expect(
      extractFixedVersion(detail, {
        name: "Flask_Login",
        version: "0.6.1",
        ecosystem: "PyPI",
      }),
    ).toBe("0.6.3");
  });
});

function makeWideProject(count: number): string {
  const root = path.join(temp, `wide-${count}`);
  const packages: Record<string, unknown> = {
    "": { name: "app", version: "1.0.0" },
  };
  for (let index = 0; index < count; index += 1) {
    packages[`node_modules/pkg-${index}`] = { version: "1.0.0" };
  }
  writeFile(
    root,
    "package-lock.json",
    JSON.stringify({ lockfileVersion: 3, packages }),
  );
  return root;
}

describe("OSV robustness", () => {
  it("fetches each advisory detail once and reuses it across packages", async () => {
    const { root } = makeProject();
    const counters = { post: 0, get: 0 };
    const result = await runSca({
      root,
      inventory: inventory(root),
      http: makeMockClient(counters),
    });
    expect(result.findings).toHaveLength(2);
    expect(result.vulnIds).toEqual(["GHSA-test-0001"]);
    expect(counters.get).toBe(1);
  });

  it("limits concurrent detail fetches to the configured concurrency", async () => {
    const root = makeWideProject(20);
    let getCount = 0;
    let inFlight = 0;
    let maxInFlight = 0;
    const client: HttpClient = {
      async postJson(_url, body) {
        const queries = (body as { queries: unknown[] }).queries;
        return {
          results: queries.map((_query, index) => ({
            vulns: [{ id: `GHSA-conc-${index}` }],
          })),
        };
      },
      async getJson() {
        getCount += 1;
        inFlight += 1;
        maxInFlight = Math.max(maxInFlight, inFlight);
        await new Promise((resolve) => setTimeout(resolve, 5));
        inFlight -= 1;
        return { affected: [] };
      },
    };
    const result = await runSca({
      root,
      inventory: inventory(root),
      http: client,
      detailConcurrency: 8,
    });
    expect(getCount).toBe(20);
    expect(result.vulnIds).toHaveLength(20);
    expect(maxInFlight).toBeLessThanOrEqual(8);
    expect(maxInFlight).toBeGreaterThan(1);
  });

  it("retries 429/5xx responses with exponential backoff", async () => {
    const { root } = makeProject();
    let postAttempts = 0;
    let getAttempts = 0;
    const delays: number[] = [];
    const client: HttpClient = {
      async postJson(_url, body) {
        postAttempts += 1;
        if (postAttempts < 3) throw new HttpError(429, "Too Many Requests");
        const queries = (body as { queries: unknown[] }).queries;
        return {
          results: queries.map(() => ({
            vulns: [{ id: "GHSA-retry-0001" }],
          })),
        };
      },
      async getJson() {
        getAttempts += 1;
        if (getAttempts === 1) throw new HttpError(503, "Service Unavailable");
        return {
          id: "GHSA-retry-0001",
          database_specific: { severity: "HIGH" },
          affected: [{ ranges: [{ events: [{ fixed: "9.0.0" }] }] }],
        };
      },
    };
    const result = await runSca({
      root,
      inventory: inventory(root),
      http: client,
      maxRetries: 3,
      retryBaseMs: 10,
      sleep: async (ms) => {
        delays.push(ms);
      },
    });
    expect(postAttempts).toBe(3);
    expect(getAttempts).toBe(2);
    expect(delays).toEqual([10, 20, 10]);
    expect(result.findings).toHaveLength(2);
    expect(result.warnings.join("\n")).not.toContain("OSV batch query failed");
    expect(result.warnings.join("\n")).not.toContain(
      "OSV vulnerability detail fetch failed",
    );
  });

  it("does not retry non-retryable HTTP errors", async () => {
    const { root } = makeProject();
    let attempts = 0;
    const client: HttpClient = {
      async postJson() {
        attempts += 1;
        throw new HttpError(400, "Bad Request");
      },
      async getJson() {
        throw new Error("should not be called");
      },
    };
    const result = await runSca({
      root,
      inventory: inventory(root),
      http: client,
      maxRetries: 3,
    });
    expect(attempts).toBe(1);
    expect(result.findings).toHaveLength(0);
    expect(result.warnings.join("\n")).toContain("OSV batch query failed");
  });
});

describe("fixture lockfiles", () => {
  it("finds the seeded vulnerable packages in fixtures", () => {
    const lock = fs.readFileSync(
      path.join(FIXTURES, "vulnerable/sca/package-lock.json"),
      "utf8",
    );
    const packages = parsePackageLock(lock, "package-lock.json");
    expect(packages.packages.map((pkg) => pkg.name)).toEqual(
      expect.arrayContaining(["lodash", "minimist"]),
    );
  });
});
