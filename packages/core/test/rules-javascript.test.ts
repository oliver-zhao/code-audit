import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { inventory } from "../src/inventory.js";
import { loadOpengrepRules } from "../src/external/opengrepRules.js";
import { classifyPath } from "../src/pathContext.js";
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
      // A path that starts with a variable is only worth a look.
      "7:js-path-api:hotspot",
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
    // '*' with credentials is refused by browsers: not reported.
    ).toEqual(["3:js-cors-credentials-any-origin:finding"]);
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

  // ---- Review of fdf8e00 on 15 more repositories (one test per item) ----

  /** Findings only (hotspots are a reading list). */
  function findingRows(lines: string[], name = "app.js"): string[] {
    return rows(lines, name).filter((row) => row.endsWith(":finding"));
  }

  it("1. skips escaped, numeric, placeholder, enum and constant SQL values", () => {
    expect(
      findingRows([
        'const mysql = require("mysql2");',
        'pool.query("SELECT * FROM t WHERE id = " + connection.escape(req.query.id));',
        'pool.query("SELECT * FROM t WHERE id = " + pool.escape(req.query.id));',
        'pool.query("SELECT * FROM t WHERE id = " + mysql.escape(req.query.id));',
        "pool.query(`SELECT * FROM t WHERE id = ${parseInt(req.params.id, 10)}`);",
        "pool.query(`SELECT * FROM t WHERE id = ${Number(req.params.id)}`);",
        "pool.query(`SELECT * FROM t WHERE id IN (${ids.map(() => '?').join(',')})`, ids);",
        "db.all(`SELECT * FROM t WHERE id IN (${placeholders})`, ids);",
        "db.run(`INSERT INTO t (a, b) VALUES ${tupleStr}`, values);",
        "db.run(`SELECT * FROM t WHERE name = ${this.escape(name)}`);",
        "db.run(`SELECT * FROM t WHERE name = ${this.quoteIdentifier(name)}`);",
        "db.all(`SELECT COUNT(*) FROM messages WHERE readStatus = ${ReadStatus.Unread}`);",
        "db.all(`DELETE FROM t WHERE key IN (${new Array(n).fill('?').join(',')})`, keys);",
      ]),
    ).toEqual([]);
  });

  it("1. reports SQL text built away from the query call as a hotspot only", () => {
    expect(
      rows([
        'const mysql = require("mysql2");',
        "const sql = `SELECT * FROM t WHERE schema = '${schemaName}'`;",
        "return `SELECT * FROM t WHERE name = '${tableName}'`;",
        "pool.query(`SELECT * FROM t WHERE name = '${tableName}'`);",
      ]),
    ).toEqual([
      "2:js-sql-string-build:hotspot",
      "3:js-sql-string-build:hotspot",
      "4:js-sql-injection:finding",
    ]);
  });

  it("2. follows request data into template literals of the -request rules", () => {
    expect(
      rows([
        'const { exec, execSync } = require("child_process");',
        'const serialize = require("node-serialize");',
        "execSync(`ls ${req.query.dir}`);",
        "exec(`convert ${opts.size} ${req.body.file} out.png`);",
        "eval(`${req.body.expr}`);",
        "fs.readFile(`/data/${req.params.name}`, cb);",
        "const re = new RegExp(`^${req.query.q}`);",
        "serialize.unserialize(`${req.cookies.profile}`);",
        "const plugin = require(`./plugins/${req.params.name}`);",
      ]),
    ).toEqual([
      "3:js-command-injection-request:finding",
      "4:js-command-injection-request:finding",
      "5:js-code-injection-request:finding",
      "6:js-path-traversal-request:finding",
      "7:js-regexp-request:hotspot",
      "8:js-deserialize-request:finding",
      "9:js-require-request:finding",
    ]);
  });

  it("3. reports request data anywhere in SQL text", () => {
    expect(
      findingRows([
        "pool.query(`SELECT * FROM users ORDER BY ${req.query.sort}`);",
        "pool.query(`SELECT * FROM users LIMIT ${req.query.limit}`);",
        "pool.query(`SELECT * FROM ${req.params.table} WHERE id = 1`);",
      ]),
    ).toEqual([
      "1:js-sql-injection-request:finding",
      "2:js-sql-injection-request:finding",
      "3:js-sql-injection-request:finding",
    ]);
  });

  it("4. matches HTTP clients case-sensitively and not their declarations", () => {
    expect(
      rows([
        "app.get('/x', handler(req));",
        "const r = new Request(url);",
        "const s = await Fetch(url);",
        "async fetch(url: string): Promise<Response> {",
        "#fetch(url) {",
        "const out = request(options);",
        "const t = got(options);",
        "const answer = await fetch(target);",
      ]),
    ).toEqual(["8:js-ssrf-api:hotspot"]);
    expect(rows(["const r = got(req.query.url);", "const s = request(req.body.target);"])).toEqual([
      "1:js-ssrf:finding",
      "2:js-ssrf:finding",
    ]);
  });

  it("4. keeps other API rules case-sensitive", () => {
    expect(
      rows([
        'const knex = require("knex");',
        "db.Query(text);",
        "const x = EVAL(code);",
        "const y = Merge({}, req.body);",
      ]),
    ).toEqual([]);
  });

  it("5. ignores eval definitions, eval() without arguments and eval in strings", () => {
    expect(
      rows([
        "  eval(source, url) {",
        "  async eval(code: string): Promise<unknown> {",
        "function eval(x) { return x; }",
        'throw new Error("this build requires eval() in development");',
        'const hint = "do not call eval(userCode) here";',
        'const msg = "new Function(code) is blocked";',
        "const result = eval(code);",
      ]),
    ).toEqual(["7:js-eval:finding"]);
  });

  it("6. treats compiled, public library and test-named paths as vendored or test code", () => {
    expect(classifyPath("packages/next/src/compiled/react/index.js")).toBe("vendored");
    expect(classifyPath("app/client/public/libraries/jquery.js")).toBe("vendored");
    expect(classifyPath("site/public/vendor/x.js")).toBe("vendored");
    expect(classifyPath("site/public/lib/y.js")).toBe("vendored");
    expect(classifyPath("src/lib/z.js")).toBeUndefined();
    expect(classifyPath("ts/test-node/sql/a.ts")).toBe("test");
    expect(classifyPath("ts/test-electron/b.ts")).toBe("test");
    expect(classifyPath("ts/sql/migrations_test.node.ts")).toBe("test");
    expect(classifyPath("ts/sql/contest.ts")).toBeUndefined();
    const lines = ['const { exec } = require("child_process");', 'exec("ls " + dir);', "eval(code);"];
    expect(
      scan({
        "packages/next/src/compiled/x.js": lines,
        "app/public/libraries/y.js": lines,
        "ts/test-node/z.ts": lines,
        "ts/a_test.node.ts": lines,
      }),
    ).toEqual([]);
  });

  it("6. skips medium findings and hotspots in files with a 1000-character line, not high or low ones", () => {
    expect(
      rows([
        'const { exec } = require("child_process");',
        `const blob = "${"x".repeat(1200)}";`,
        'exec("ls " + dir);',
        "eval(code);",
        'exec("ping " + req.body.host);',
      ]),
    ).toEqual(["4:js-eval:finding", "5:js-command-injection-request:finding"]);
  });

  it("7. needs a directory literal before the runtime part of a path", () => {
    expect(
      rows([
        "app.get('/', (req, res) => {});",
        "fs.readFileSync(`${dir}/index.js`);",
        "fs.readFile(chunkPath + '.map', cb);",
        "fs.readFile('/' + mainName, cb);",
        "fs.readFile(`/proc/${pid}/stat`, cb);",
        "fs.readFile('/data/' + name, cb);",
      ]),
    ).toEqual([
      "2:js-path-api:hotspot",
      "3:js-path-api:hotspot",
      "4:js-path-api:hotspot",
      "5:js-path-api:hotspot",
      "6:js-path-traversal:finding",
    ]);
  });

  it("8. leaves TLS options in examples and build scripts alone", () => {
    const lines = ["const agent = new https.Agent({ rejectUnauthorized: false });"];
    expect(
      scan({ "examples/complex/scripts/setup.ts": lines, "scripts/dev.js": lines, "src/client.js": lines }),
    ).toEqual(["src/client.js:1:js-tls-disabled:finding"]);
  });

  it("9. does not report '*' with credentials, which browsers refuse", () => {
    expect(
      rows([
        "app.use(cors({ origin: '*', credentials: true }));",
        "res.setHeader('Access-Control-Allow-Origin', '*');",
        "res.setHeader('Access-Control-Allow-Credentials', 'true');",
        "res.setHeader('Access-Control-Allow-Origin', req.headers.origin);",
      ]),
    ).toEqual(["4:js-cors-header-credentials:finding"]);
  });

  it("10. reports nodeIntegrationInSubFrames on its own as a hotspot", () => {
    expect(
      rows([
        "new BrowserWindow({ webPreferences: { sandbox: true, nodeIntegration: false, nodeIntegrationInSubFrames: true } });",
        "new BrowserWindow({ webPreferences: { nodeIntegration: true } });",
      ]),
    ).toEqual(["1:js-electron-node-integration-frames:hotspot", "2:js-electron-node-integration:finding"]);
  });

  it("12. lets the Opengrep pattern and taint rules collapse (same CWE)", () => {
    const rules = loadOpengrepRules(path.join(RULES_DIR, "opengrep")).rules;
    const cwe = (id: string): string | undefined => rules.find((rule) => rule.id === id)?.cwe;
    expect(cwe("js-opengrep-eval")).toBe(cwe("js-opengrep-req-code"));
    expect(cwe("js-opengrep-child-process-exec")).toBe(cwe("js-opengrep-req-command"));
  });

  it("13. gates js-path-api on request handlers and skips signatures and constants", () => {
    expect(rows(["fs.readFile(file, cb);"], "lib/util.js")).toEqual([]);
    expect(
      rows([
        "app.get('/', (req, res) => {});",
        "async readFile(path: string): Promise<Buffer> {",
        "fs.readFile(file, cb);",
      ]),
    ).toEqual(["3:js-path-api:hotspot"]);
    expect(rows(['const knex = require("knex");', "await knex.raw(CREATE_TABLE_SQL);", "await knex.raw(sql);"])).toEqual([
      "3:js-sql-api:hotspot",
    ]);
  });

  it("14. does not report a quoted or numeric command value", () => {
    expect(
      rows([
        'const { exec, execSync } = require("child_process");',
        'const quote = require("shell-quote").quote;',
      ]).concat(
        rows([
          'const { exec, execSync } = require("child_process");',
          "exec('lsof -p ' + this.proc.pid + ' | grep cwd');",
          'execSync(`"${binaryPath}" -CAROOT`);',
          "execSync(`${manager} --version`);",
          "exec('git log ' + ref);",
        ]),
      ),
    ).toEqual([
      "2:js-exec-api:hotspot",
      "3:js-exec-api:hotspot",
      "4:js-exec-api:hotspot",
      "5:js-command-injection:finding",
    ]);
    expect(
      rows(['const { exec } = require("child_process");', "exec('tar xzf ' + shellQuote([name]));"]),
    ).toEqual(["2:js-exec-api:hotspot"]);
  });

  it("15. files helmet CSP under CWE-693", () => {
    expect(jsRules.find((rule) => rule.id === "js-helmet-csp-disabled")?.cwe).toBe("CWE-693");
  });

  it("covers Koa ctx.body, Fastify text/html, Next.js and axios({ url })", () => {
    expect(
      rows([
        "ctx.body = `<h1>${ctx.query.name}</h1>`;",
        "ctx.body = `${ctx.query.name}`;",
        "reply.type('text/html').send(`<p>${request.query.name}</p>`);",
        "return NextResponse.redirect(request.nextUrl.searchParams.get('next'));",
        "const r7 = await axios({ url: req.body.url });",
      ], "route.ts"),
    ).toEqual([
      "1:js-res-send-xss:finding",
      "3:js-res-send-xss:finding",
      "4:js-open-redirect:finding",
      "5:js-ssrf:finding",
    ]);
  });


  // The C-family lexer removes comments and joins a statement while ( or [
  // (or an object literal passed as an argument) is open.
  it("reports cors({ ... }) when origin and credentials are on different lines", () => {
    expect(
      rows(["const cors = require('cors');", "app.use(cors({", "  origin: true,", "  credentials: true,", "}));"]),
    ).toEqual(["2:js-cors-credentials-any-origin:finding"]);
  });
  it("reports exec(\\n  \"ls \" + dir\\n) when the argument is on the next line", () => {
    expect(
      rows(["const { exec } = require('child_process');", "exec(", '  "ls " + dir', ");"]),
    ).toEqual(["2:js-command-injection:finding"]);
  });
  it("ignores a sink inside a trailing comment: run(); // eval(req.body.x)", () => {
    expect(rows(["run(); // eval(req.body.x)", "/* eval(req.body.y)", "   eval(req.query.z) */"])).toEqual([]);
  });
  it("reports cookie: {\\n secure: false } in an express-session options object", () => {
    expect(
      rows([
        "app.use(session({",
        "  secret: process.env.SESSION_SECRET,",
        "  cookie: {",
        "    httpOnly: true,",
        "    secure: false,",
        "  },",
        "}));",
      ]),
    ).toEqual(["3:js-cookie-insecure:finding"]);
    expect(rows(["app.use(session({", "  cookie: {", "    secure: true,", "  },", "}));"])).toEqual([]);
  });
  it("reports jwt.verify without algorithms only when no options object follows on later lines", () => {
    const head = ["const jwt = require('jsonwebtoken');"];
    expect(rows([...head, "jwt.verify(token, key, {", "  algorithms: ['RS256'],", "});"])).toEqual([]);
    expect(rows([...head, "jwt.verify(", "  token,", "  key,", ");"])).toEqual(["2:js-jwt-verify-no-algorithms:hotspot"]);
  });
  // Not a rule limitation: .vue, .svelte, .ejs, .hbs and .html files are not
  // assigned a language (packages/core/src/language.ts), so their scripts and
  // templates (v-html, {@html}, <%- %>, {{{ }}}) are not scanned.
  it.todo("scans <script> blocks of .vue / .svelte files and server templates");
});
