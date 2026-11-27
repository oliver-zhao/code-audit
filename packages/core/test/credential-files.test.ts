/**
 * Credentials that are separated from their name by whitespace, or that are a
 * credential only by their position in a file, must be masked everywhere a
 * line of the repository is shown: every report file of a scan and the
 * `read` / `search` commands. Unambiguous credential files are also reported.
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { redactLine } from "../src/redact.js";
import { readSnippet, searchCode } from "../src/runstore.js";
import { scanProject, type ScanResult } from "../src/scan.js";
import { CLI, cleanup, makeTempDir, readAllOutputFiles, writeFile } from "./helpers.js";

const temp = makeTempDir("credfiles");
const project = path.join(temp, "project");
afterAll(() => cleanup(temp));

/** Every secret is unique, so a leak names the line it came from. */
let counter = 0;
const secrets: string[] = [];
function secret(): string {
  counter += 1;
  const value = `Zq${counter}xK7pW${counter}mR4t`;
  secrets.push(value);
  return value;
}
/** A secret with no digit: only its position makes it a credential. */
function wordSecret(): string {
  counter += 1;
  const value = `${"correcthorsebattery".slice(0, 12)}${"abcdefghijklmnopqrstuvwxyz"[counter % 26]}${"zyxwvutsrqponmlkjihgfedcba"[(counter * 7) % 26]}staple`;
  secrets.push(value);
  return value;
}
function base64Secret(): string {
  const value = Buffer.from(`user:${secret()}`).toString("base64");
  secrets.push(value);
  return value;
}

const FILES: Record<string, string[]> = {};
function file(name: string, lines: string[]): void {
  FILES[name] = lines;
}

file(".netrc", [
  `machine api.example.com login oliver password ${secret()}`,
  "machine other.example.com",
  "  login deploy",
  `  password ${wordSecret()}`,
  `default login anonymous password ${secret()} account ${secret()}`,
]);
file("home/_netrc", [`machine x login y password "${secret()}"`]);
file(".pgpass", [
  "# hostname:port:database:username:password",
  `db.example.com:5432:mydb:myuser:${secret()}`,
  `*:*:*:postgres:${wordSecret()}`,
]);
file(".npmrc", [
  "registry=https://registry.example.com/",
  `//registry.example.com/:_authToken=${secret()}`,
  `_auth=${base64Secret()}`,
  `//other.example.com/:_password=${base64Secret()}`,
  "//safe.example.com/:_authToken=${NPM_TOKEN}",
]);
file(".pypirc", ["[pypi]", "username = __token__", `password = ${secret()}`, "[testpypi]", `password: ${wordSecret()}`]);
file("deploy/pip.conf", ["[global]", `password = ${secret()}`]);
file("docker/config.json", [
  "{",
  '  "auths": {',
  '    "registry.example.com": {',
  `      "auth": "${base64Secret()}"`,
  "    },",
  `    "other.example.com": { "identitytoken": "${secret()}" }`,
  "  }",
  "}",
]);
file("cluster/kubeconfig", [
  "apiVersion: v1",
  "kind: Config",
  "users:",
  "- name: admin",
  "  user:",
  `    token: ${secret()}`,
  `    client-key-data: ${base64Secret()}`,
  `    password: ${wordSecret()}`,
]);
file("k8s/admin.conf", [
  "apiVersion: v1",
  "clusters: []",
  "kind: Config",
  "users:",
  "- name: admin",
  "  user:",
  `    client-key-data: ${base64Secret()}`,
]);
file("conf/redis.conf", [`requirepass ${wordSecret()}`, `masterauth ${secret()}`, "port 6379"]);
file("conf/app.conf", [`password ${wordSecret()}`, `  secret   ${secret()}`, `api_key "${wordSecret()}"`]);
file("scripts/deploy.sh", [
  "#!/bin/sh",
  `sshpass -p ${secret()} ssh deploy@host true`,
  `sshpass -p '${secret()}' scp a host:`,
  `mysql -u root -p${secret()} app < dump.sql`,
  `mysqldump -h db -u root -p ${secret()} app`,
  `docker login -u ci -p ${secret()} registry.example.com`,
  `echo "${secret()}" | docker login -u ci --password-stdin registry.example.com`,
  `redis-cli -h cache -a ${secret()} ping`,
  `htpasswd -b /etc/nginx/.htpasswd admin ${secret()}`,
  `curl -u admin:${secret()} https://api.example.com/`,
  `curl --user "admin:${secret()}" https://api.example.com/`,
  `PGPASSWORD=${secret()} psql -h db`,
  `tool --password ${secret()} --verbose`,
  `tool -H "Authorization: Basic ${base64Secret()}"`,
]);
file("docs/notes.txt", [
  `The password is ${secret()} for now.`,
  `admin password ${secret()}`,
  `Authorization: Basic ${base64Secret()}`,
  `Cookie: session=${secret()}; theme=dark`,
  `Set-Cookie: sid=${secret()}; Path=/; HttpOnly`,
  "The password must be at least twelve characters long.",
]);
file("src/app.py", [`# staging password ${secret()}`, "import os", "print('hello')"]);
file("web/.htpasswd", [`admin:$apr1$${secret()}$abcdefghijklmnop`]);

let scan: ScanResult;

beforeAll(async () => {
  for (const [name, lines] of Object.entries(FILES)) writeFile(project, name, `${lines.join("\n")}\n`);
  scan = await scanProject({
    root: project,
    offline: true,
    engines: ["builtin"],
    formats: ["md", "json", "sarif"],
    untrusted: true,
  });
});

function leaks(text: string): string[] {
  return secrets.filter((value) => text.includes(value));
}

describe("whitespace-separated and positional credentials are masked", () => {
  it("has a test secret on every line that should hold one", () => {
    expect(secrets.length).toBeGreaterThan(45);
    expect(new Set(secrets).size).toBe(secrets.length);
  });

  it("in every file a scan writes", () => {
    const output = readAllOutputFiles(scan.runDir);
    expect(output.length).toBeGreaterThan(1000);
    expect(leaks(output)).toEqual([]);
  });

  it("in read, for every line of every file", () => {
    for (const name of Object.keys(FILES)) {
      const snippet = readSnippet(scan.runId, name, 1, 400, { cwd: project });
      expect(leaks(snippet.content), name).toEqual([]);
      // Not everything is masked: the structure of the file stays readable.
      expect(snippet.content.length, name).toBeGreaterThan(10);
    }
    const netrc = readSnippet(scan.runId, ".netrc", 1, 10, { cwd: project }).content;
    expect(netrc).toMatch(/machine api\.example\.com login oliver password \*+/);
    const prose = readSnippet(scan.runId, "docs/notes.txt", 1, 10, { cwd: project }).content;
    expect(prose).toContain("The password must be at least twelve characters long.");
    expect(prose).toContain("theme=");
  });

  it("in search, literal and regex", () => {
    for (const input of [
      { pattern: "password" },
      { pattern: "pass", regex: true },
      { pattern: "auth" },
      { pattern: "-p", maxResults: 200 },
      { pattern: "token" },
      { pattern: "Cookie" },
      { pattern: ":", maxResults: 200 },
      { pattern: ".", regex: true, maxResults: 200 },
    ]) {
      const result = searchCode(scan.runId, input, { cwd: project });
      expect(result.total, input.pattern).toBeGreaterThan(0);
      expect(leaks(JSON.stringify(result)), input.pattern).toEqual([]);
    }
  });

  it("in the output of the read and search commands", () => {
    for (const name of Object.keys(FILES)) {
      const read = spawnSync(process.execPath, [CLI, "read", scan.runId, name], { cwd: project, encoding: "utf8" });
      expect(read.status, `${name}: ${read.stderr}`).toBe(0);
      expect(leaks(read.stdout + read.stderr), name).toEqual([]);
      const json = spawnSync(process.execPath, [CLI, "read", scan.runId, name, "--json"], {
        cwd: project,
        encoding: "utf8",
      });
      expect(leaks(json.stdout), name).toEqual([]);
    }
    for (const args of [["password"], ["pass|auth|token|-p|:", "--regex", "--max-results", "200"]]) {
      const search = spawnSync(process.execPath, [CLI, "search", scan.runId, ...args], {
        cwd: project,
        encoding: "utf8",
      });
      expect(search.status, search.stderr).toBe(0);
      expect(leaks(search.stdout + search.stderr), args.join(" ")).toEqual([]);
    }
    // Spawns ~30 CLI processes; each loads every rule. Slow CI hosts need more
    // than the default 30 s.
  }, 180_000);

  it("without a file name where the form itself is enough", () => {
    for (const line of [
      "sshpass -p S3cr3tV4lu3xyz ssh host",
      "mysql -u root -pS3cr3tV4lu3xyz db",
      "curl -u admin:S3cr3tV4lu3xyz https://x",
      "the password is S3cr3tV4lu3xyz",
      "Cookie: session=S3cr3tV4lu3xyz",
      "    client-key-data: UzNjcjN0VjRsdTN4eXo=",
    ]) {
      const redacted = redactLine(line);
      expect(redacted, line).not.toMatch(/S3cr3tV4lu3xyz|UzNjcjN0VjRsdTN4eXo/);
    }
    // References and plain prose stay readable.
    expect(redactLine('sshpass -p "$SSH_PASSWORD" ssh host')).toContain("$SSH_PASSWORD");
    expect(redactLine("curl -u admin:${API_PASSWORD} https://x")).toContain("${API_PASSWORD}");
    expect(redactLine("password required for login")).toBe("password required for login");
    expect(redactLine("token: str = load()")).toBe("token: str = load()");
  });
});

describe("credential files are reported", () => {
  const expected: Array<[string, string, number]> = [
    ["secret-netrc-password", ".netrc", 1],
    ["secret-netrc-password", ".netrc", 4],
    ["secret-netrc-password", ".netrc", 5],
    ["secret-netrc-password", "home/_netrc", 1],
    ["secret-pgpass-password", ".pgpass", 2],
    ["secret-pgpass-password", ".pgpass", 3],
    ["secret-npmrc-auth", ".npmrc", 2],
    ["secret-npmrc-auth", ".npmrc", 3],
    ["secret-npmrc-auth", ".npmrc", 4],
    ["secret-pypirc-password", ".pypirc", 3],
    ["secret-pypirc-password", ".pypirc", 5],
    ["secret-pypirc-password", "deploy/pip.conf", 2],
    ["secret-docker-auth", "docker/config.json", 4],
    ["secret-docker-auth", "docker/config.json", 6],
    ["secret-kubeconfig-credential", "cluster/kubeconfig", 6],
    ["secret-kubeconfig-credential", "cluster/kubeconfig", 7],
    ["secret-kubeconfig-credential", "cluster/kubeconfig", 8],
    ["secret-kubeconfig-credential", "k8s/admin.conf", 7],
  ];

  it("one finding per credential, with masked evidence", () => {
    const found = scan.findings.map((finding) => `${finding.ruleId} ${finding.file}:${finding.startLine}`);
    for (const [ruleId, name, line] of expected) {
      expect(found, `${ruleId} ${name}:${line}`).toContain(`${ruleId} ${name}:${line}`);
    }
    for (const finding of scan.findings) {
      expect(leaks(finding.evidence), `${finding.ruleId} ${finding.file}:${finding.startLine}`).toEqual([]);
    }
  });

  it("not for a reference to the environment or a comment", () => {
    const found = scan.findings.map((finding) => `${finding.file}:${finding.startLine}`);
    expect(found).not.toContain(".npmrc:5");
    expect(found).not.toContain(".pgpass:1");
    expect(scan.findings.filter((finding) => finding.file === ".npmrc" && finding.startLine === 2)).toHaveLength(1);
  });
});

describe("credential directories as audit roots (command line)", () => {
  const home = path.join(temp, "home");
  const env = { ...process.env, HOME: home, USERPROFILE: home };
  const run = (args: string[], cwd = home) =>
    spawnSync(process.execPath, [CLI, ...args], { cwd, encoding: "utf8", env });

  beforeAll(() => {
    writeFile(home, ".aws/credentials", "[default]\naws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n");
    writeFile(home, ".config/tool/settings.py", "import os\nos.system(cmd)\n");
    writeFile(home, "work/app/main.py", "import os\nos.system(cmd)\n");
    fs.symlinkSync(path.join(home, ".aws"), path.join(home, "work", "innocent"), "dir");
  });

  it("refuses them without --allow-sensitive-root and writes nothing", () => {
    for (const root of [".aws", ".config", ".config/tool", "work/innocent", "."]) {
      const result = run(["scan", root, "--offline", "--engines", "builtin"]);
      expect(result.status, root).toBe(2);
      expect(result.stderr, root).toMatch(
        root === "." ? /home directory/ : /credentials or machine configuration.*--allow-sensitive-root/s,
      );
      expect(fs.existsSync(path.join(home, root, ".audit")), root).toBe(false);
    }
    expect([0, 1]).toContain(run(["scan", "work/app", "--offline", "--engines", "builtin"]).status);
  });

  it("audits one when the user says so, and needs the flag again to read its files", () => {
    const scan = run(["scan", ".config/tool", "--offline", "--engines", "builtin", "--allow-sensitive-root"]);
    expect([0, 1], scan.stderr).toContain(scan.status);
    const root = path.join(home, ".config/tool");
    const runId = fs.readdirSync(path.join(root, ".audit")).find((name) => name !== "index.json") as string;
    expect(run(["status", runId], root).status).toBe(0);
    const refused = run(["read", runId, "settings.py"], root);
    expect(refused.status).toBe(2);
    expect(refused.stderr).toMatch(/--allow-sensitive-root/);
    const allowed = run(["read", runId, "settings.py", "--allow-sensitive-root"], root);
    expect(allowed.status, allowed.stderr).toBe(0);
    expect(allowed.stdout).toContain("os.system(cmd)");
    // The flag covers that directory only.
    expect(run(["scan", ".aws", "--offline", "--engines", "builtin"]).status).toBe(2);
  });
});
