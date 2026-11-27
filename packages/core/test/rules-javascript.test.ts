import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { inventory } from "../src/inventory.js";
import { loadRules, scanRules } from "../src/rules.js";
import {
  CLEAN,
  RULES_DIR,
  VULNERABLE,
  cleanup,
  loadExpected,
  makeTempDir,
  writeFile,
} from "./helpers.js";

const temp = makeTempDir("rules-javascript");
afterAll(() => cleanup(temp));

const ruleSet = loadRules(RULES_DIR);
const jsRules = ruleSet.rules.filter((rule) => rule.id.startsWith("js-"));
const JS_FIXTURE = /^(?:api\/)?javascript\//;

let counter = 0;
/** Scan one throw-away project and return `line:rule-id:kind` rows of the js- rules. */
function scan(files: Record<string, string[]>): string[] {
  counter += 1;
  const project = path.join(temp, `case-${counter}`);
  for (const [name, lines] of Object.entries(files)) {
    writeFile(project, name, [...lines, ""].join("\n"));
  }
  const result = scanRules(inventory(project).files, ruleSet);
  return result.hits
    .filter((hit) => hit.rule.id.startsWith("js-"))
    .map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}:${hit.rule.kind}`)
    .sort();
}

/** Rows of a single file `app.js` (or the given name), without the file part. */
function rows(lines: string[], name = "app.js"): string[] {
  return scan({ [name]: lines }).map((row) => row.slice(name.length + 1));
}

describe("JavaScript rule set", () => {
  it("has bilingual text, CWE, OWASP and both languages on every rule", () => {
    expect(jsRules.length).toBeGreaterThanOrEqual(60);
    for (const rule of jsRules) {
      expect(rule.title_zh, rule.id).toBeTruthy();
      expect(rule.message_zh, rule.id).toBeTruthy();
      expect(rule.remediation_zh, rule.id).toBeTruthy();
      expect(rule.cwe, rule.id).toMatch(/^CWE-\d+$/);
      expect(rule.owasp, rule.id).toMatch(/^A\d{2}:2021$/);
      expect([...rule.languages].sort(), rule.id).toEqual(["javascript", "typescript"]);
      // Policy: a hotspot is always low confidence.
      if (rule.kind === "hotspot") expect(rule.confidence, rule.id).toBe("low");
    }
  });

  it("lists exactly the results of the JavaScript fixtures in EXPECTED.json", () => {
    const expected = loadExpected()
      .seeds.filter((seed) => JS_FIXTURE.test(seed.file))
      .map((seed) => `${seed.file}:${seed.line}:${seed.ruleId}:${seed.kind ?? "finding"}`)
      .sort();
    const result = scanRules(
      inventory(VULNERABLE).files.filter((file) => JS_FIXTURE.test(file.relPath)),
      ruleSet,
    );
    const actual = result.hits
      .map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}:${hit.rule.kind}`)
      .sort();
    expect(actual).toEqual(expected);
    // Every js- rule is seeded in these fixtures.
    const seeded = new Set(expected.map((row) => row.split(":")[2]));
    expect(jsRules.map((rule) => rule.id).filter((id) => !seeded.has(id))).toEqual([]);
  });

  it("finds nothing but two reviewed low hotspots in the clean JavaScript fixtures", () => {
    const result = scanRules(
      inventory(CLEAN).files.filter((file) => JS_FIXTURE.test(file.relPath)),
      ruleSet,
    );
    expect(result.hits.filter((hit) => hit.rule.kind === "finding")).toEqual([]);
    expect(
      result.hits.map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}`).sort(),
    ).toEqual([
      // Identifier interpolation in DDL and a basename-checked name: a reviewer reads them.
      "javascript/db.ts:21:js-sql-api",
      "javascript/web.js:20:js-path-api",
    ]);
  });

  it("masks hard-coded keys and secrets in the evidence", () => {
    const project = path.join(temp, "redact");
    writeFile(
      project,
      "keys.js",
      [
        'const crypto = require("crypto");',
        'const jwt = require("jsonwebtoken");',
        'const session = require("express-session");',
        'crypto.createHmac("sha256", "hmac-signing-key-1234");',
        'jwt.sign(payload, "jwt-signing-secret-1");',
        'app.use(session({ secret: "keyboard-cat-session" }));',
        "",
      ].join("\n"),
    );
    const hits = scanRules(inventory(project).files, ruleSet).hits;
    expect(hits.map((hit) => hit.rule.id).sort()).toEqual([
      "js-hardcoded-crypto-key",
      "js-jwt-hardcoded-secret",
      "js-session-hardcoded-secret",
    ]);
    for (const hit of hits) {
      expect(hit.evidence).not.toMatch(/hmac-signing-key|jwt-signing-secret|keyboard-cat-session/);
    }
  });
});

describe("JavaScript rule precision", () => {
  it("does not treat string literals, declarations or other receivers as sinks", () => {
    expect(
      rows([
        'const { exec } = require("child_process");',
        'const note = "eval(req.body.x) is unsafe";',
        "const match = /(\\d+)/.exec(req.query.text);",
        "const rows = await query.exec();",
        "function readFile(name) { return name; }",
        "async function fetch(url) { return url; }",
        'eval("1 + 1");',
        'exec("ls -l");',
        "function wrapper(callback) { return callback; }",
        "const fn = new Function(\"a\", \"b\", \"return a + b\");",
      ]),
    ).toEqual([]);
  });

  it("skips whole-line comments and JSDoc examples", () => {
    expect(
      rows([
        'const { exec } = require("child_process");',
        "// exec(\"ls \" + req.query.dir);",
        "/* eval(req.body.code) */",
        " * res.sendFile('/uploads/' + uid + '/' + file);",
        " *   db.query(\"SELECT * FROM t WHERE a = '\" + req.query.a + \"'\");",
      ]),
    ).toEqual([]);
  });

  it("keeps SQL keywords case-aware and ignores constants and tagged templates", () => {
    expect(
      rows([
        'const mysql = require("mysql2");',
        'const label = "Select an item from the list: " + req.query.item;',
        'const sql1 = "SELECT * FROM t WHERE id = ?";',
        "await db.query(sql`SELECT * FROM t WHERE id = ${req.params.id}`);",
        "await prisma.$queryRaw`SELECT * FROM t WHERE id = ${req.params.id}`;",
        "await db.raw(`select * from sqlite_master where name = '${INDEX_NAME}'`);",
        "const q = 'SELECT * FROM t WHERE ids IN (' +",
        '  "SELECT id FROM u WHERE flag = ?)";',
        'await pool.query("SELECT " + columns.join(", ") + " FROM t WHERE id = ?", [id]);',
        "await qb.where(`${alias}.id = :id`, { id });",
      ]),
      // A template with an interpolation is still worth a look, not a finding.
    ).toEqual(["6:js-sql-api:hotspot"]);
    // Lower-case SQL is still SQL.
    expect(
      rows([
        'const mysql = require("mysql2");',
        "pool.query(\"select * from users where name = '\" + name + \"'\");",
        "pool.query(`delete from users where id = ${req.query.id}`);",
      ]),
    ).toEqual(["2:js-sql-injection:finding", "3:js-sql-injection-request:finding"]);
  });

  it("does not report SQL in migrations or build tooling, but does report in services", () => {
    const sql = ["const knex = require(\"knex\");", "await knex.raw(`SELECT * FROM t WHERE id = ${id}`);"];
    expect(
      scan({
        "db/migrations/001-init.js": sql,
        "scripts/seed-dev.js": sql,
        "src/service.js": sql,
      }),
    ).toEqual(["src/service.js:2:js-sql-injection:finding"]);
  });

  it("does not report test, example or minified files", () => {
    const lines = [
      'const { exec } = require("child_process");',
      "exec(\"ping \" + req.body.host);",
      "res.send(\"<p>\" + req.query.name + \"</p>\");",
    ];
    expect(
      scan({
        "test/app.test.js": lines,
        "src/app.spec.ts": lines,
        "public/vendor.min.js": lines,
        "examples/demo/app.js": ['app.use(session({ secret: "keyboard-cat-session" }));', 'const s = require("express-session");'],
        "src/app.js": lines,
      }),
    ).toEqual([
      "src/app.js:2:js-command-injection-request:finding",
      "src/app.js:3:js-res-send-xss:finding",
    ]);
  });

  it("separates request data, runtime values and constants for paths", () => {
    expect(
      rows([
        'const fs = require("fs");',
        "fs.readFile(__dirname + \"/templates/mail.html\", cb);",
        "res.sendFile(path.join(__dirname, \"public\", \"index.html\"));",
        "res.sendFile(req.params.file, { root: UPLOADS });",
        "fs.readFile(path.join(UPLOADS, path.basename(req.query.name)), cb);",
        "fs.readFile(\"/data/\" + name, cb);",
        "fs.readFile(`${base}/${name}`, cb);",
        "fs.readFile(path.join(__dirname, req.query.name), cb);",
        "ctx.body = fs.createReadStream(ctx.query.file);",
      ]),
    ).toEqual([
      "6:js-path-traversal:finding",
      "7:js-path-traversal:finding",
      "8:js-path-traversal-request:finding",
      "9:js-path-traversal-request:finding",
    ]);
  });

  it("reports redirects to request data but not back to the referrer or to a local path", () => {
    expect(
      rows([
        "app.get('/a', (req, res) => res.redirect(req.query.next));",
        "app.get('/b', (req, res) => res.redirect(req.get('Referrer') || '/'));",
        "app.get('/c', (req, res) => res.redirect('/user/' + id));",
        "app.get('/d', (req, res) => res.redirect(301, '/home'));",
        "app.get('/e', (req, res) => res.redirect(target));",
      ]),
    ).toEqual(["1:js-open-redirect:finding", "2:js-redirect-api:hotspot", "5:js-redirect-api:hotspot"]);
  });

  it("only reports res.send XSS for a property of the request, not for an escaped value or the body", () => {
    expect(
      rows([
        "res.send(\"<h1>\" + req.query.name + \"</h1>\");",
        "res.send(\"<h1>\" + escapeHtml(req.query.name) + \"</h1>\");",
        "res.send(req.body);",
        "res.json({ name: req.query.name });",
      ]),
    ).toEqual(["1:js-res-send-xss:finding"]);
  });

  it("separates DOM sinks fed by the URL from other runtime HTML and from literals", () => {
    expect(
      rows([
        "el.innerHTML = '';",
        "el.innerHTML = \"<b>static</b>\";",
        "if (el.innerHTML === html) {}",
        "el.innerHTML = DOMPurify.sanitize(html);",
        "el.innerHTML = html;",
        "el.innerHTML = location.hash.slice(1);",
        "$('#a').attr('href', location.href);",
      ]),
    ).toEqual(["5:js-dom-xss-html:hotspot", "6:js-dom-xss-source:finding"]);
  });

  it("needs origin and credentials in one cors() call", () => {
    expect(
      rows([
        "const ENABLE_CORS = { origin: true, credentials: true };",
        "app.use(cors({ origin: [\"https://a.example\"], credentials: true }));",
        "app.use(cors({ credentials: true, origin: true }));",
        "const io = new Server(http, { cors: { origin: \"*\", credentials: true } });",
      ]),
    ).toEqual(["3:js-cors-credentials-any-origin:finding", "4:js-cors-credentials-any-origin:finding"]);
  });

  it("tells Math.random for secrets from Math.random for other values", () => {
    expect(
      rows([
        "const resetToken = Math.random().toString(36);",
        "const csrfSecret = Math.random();",
        "const tokenIndex = Math.floor(Math.random() * tokens.length);",
        "const jitter = Math.random() * 100;",
        "if (token === Math.random()) {}",
      ]),
    ).toEqual(["1:js-weak-random:finding", "2:js-weak-random:finding"]);
  });

  it("checks the PBKDF2 iteration count and the cipher name", () => {
    expect(
      rows([
        "crypto.pbkdf2Sync(pw, salt, 1000, 32, \"sha256\");",
        "crypto.pbkdf2Sync(pw, salt, 600000, 32, \"sha256\");",
        "crypto.pbkdf2Sync(pw, salt, ITERATIONS, 32, \"sha256\");",
        "crypto.createCipheriv(\"aes-256-gcm\", key, iv);",
        "crypto.createCipheriv(\"bf-cbc\", key, iv);",
        "crypto.createDecipheriv(\"aes-256-ecb\", key, null);",
      ]),
    ).toEqual(["1:js-pbkdf2-low-iterations:finding", "5:js-weak-cipher:finding", "6:js-weak-cipher:finding"]);
  });

  it("reports exec with concatenation only in files that use child_process", () => {
    expect(rows(["const runner = makeRunner();", "exec(\"ls \" + dir);"])).toEqual([]);
    expect(
      rows([
        "import { exec, execSync } from \"node:child_process\";",
        "exec(\"ls \" + dir);",
        "execSync(`ls ${dir}`);",
        "execSync(`ls ${__dirname}`);",
        "exec(__dirname + \"/run.sh\");",
      ]),
    ).toEqual(["2:js-command-injection:finding", "3:js-command-injection:finding"]);
  });

  it("uses Function only for the constructor, not for function declarations", () => {
    expect(
      rows([
        "const handler = function (req, res) { return req.query.x; };",
        "app.get('/', function(req, res) { res.json(req.query); });",
        "const f = Function(req.query.code);",
      ]),
    ).toEqual(["3:js-code-injection-request:finding"]);
  });

  it("covers Koa, TypeScript and Next-style handlers", () => {
    expect(
      scan({
        "src/routes.ts": [
          "router.get('/x', async (ctx) => {",
          "  ctx.redirect(ctx.query.next as string);",
          "  const value = eval(ctx.request.body.expr);",
          "});",
        ],
      }),
    ).toEqual([
      "src/routes.ts:2:js-open-redirect:finding",
      "src/routes.ts:3:js-code-injection-request:finding",
    ]);
  });

  it("gates postMessage, jwt.verify and js-yaml hotspots on the file", () => {
    expect(
      rows([
        "window.addEventListener('message', (e) => {",
        "  if (e.origin !== 'https://a.example') return;",
        "});",
        "jwt.verify(token, key);",
        "yaml.load(text);",
      ]),
    ).toEqual([]);
    expect(
      rows(["const yaml = require('js-yaml');", "yaml.load(text);", "yaml.load(text, { schema: yaml.JSON_SCHEMA });"]),
    ).toEqual(["2:js-yaml-load:hotspot"]);
  });

  // The engine matches one physical line today. A C-family lexer (comments
  // removed, statements joined while ( or [ is open) will make these work.
  it.todo("reports cors({ ... }) when origin and credentials are on different lines");
  it.todo("reports exec(\\n  \"ls \" + dir\\n) when the argument is on the next line");
  it.todo("ignores a sink inside a trailing comment: run(); // eval(req.body.x)");
  it.todo("reports cookie: {\\n secure: false } in an express-session options object");
  it.todo("reports jwt.verify without algorithms only when no options object follows on later lines");
  // Not a rule limitation: .vue, .svelte, .ejs, .hbs and .html files are not
  // assigned a language (packages/core/src/language.ts), so their scripts and
  // templates (v-html, {@html}, <%- %>, {{{ }}}) are not scanned.
  it.todo("scans <script> blocks of .vue / .svelte files and server templates");
});
