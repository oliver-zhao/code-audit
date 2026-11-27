import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { inventory } from "../src/inventory.js";
import { classifyPath } from "../src/pathContext.js";
import { SOURCE_LANGUAGES, detectLanguage, languageDisplayName } from "../src/language.js";
import { RULE_LANGUAGES, loadRules, scanRules } from "../src/rules.js";
import { scanProject } from "../src/scan.js";
import {
  CLEAN,
  RULES_DIR,
  VULNERABLE,
  cleanup,
  loadExpected,
  makeTempDir,
  readAllOutputFiles,
  writeFile,
} from "./helpers.js";

const temp = makeTempDir("rules-rust");
afterAll(() => cleanup(temp));

const ruleSet = loadRules(RULES_DIR);
const rustRules = ruleSet.rules.filter((rule) => rule.id.startsWith("rs-"));

let caseCounter = 0;
/** Scan one Rust file at `relPath` and return `line:ruleId` for every rs- hit. */
function rustHits(relPath: string, lines: string[]): string[] {
  caseCounter += 1;
  const project = path.join(temp, `case-${caseCounter}`);
  writeFile(project, relPath, `${lines.join("\n")}\n`);
  const result = scanRules(inventory(project).files, ruleSet);
  return result.hits
    .filter((hit) => hit.rule.id.startsWith("rs-"))
    .map((hit) => `${hit.line}:${hit.rule.id}`);
}

const ids = (hits: string[]): string[] => hits.map((hit) => hit.split(":")[1] as string);

describe("Rust language registration", () => {
  it("detects .rs files as rust and counts them as source", () => {
    expect(detectLanguage("src/main.rs")).toBe("rust");
    expect(detectLanguage("crates/a/src/lib.RS")).toBe("rust");
    expect(detectLanguage("Cargo.toml")).not.toBe("rust");
    expect(SOURCE_LANGUAGES).toContain("rust");
    expect(RULE_LANGUAGES).toContain("rust");
    expect(languageDisplayName("rust")).toBe("Rust");
  });

  it("reports LOC for .rs files and leaves out the target/ build directory", () => {
    const project = path.join(temp, "inventory");
    writeFile(project, "src/main.rs", "fn main() {\n    println!(\"hi\");\n}\n");
    writeFile(project, "target/debug/build/gen/out.rs", "fn generated() {}\n");
    const inv = inventory(project);
    const rust = inv.files.filter((file) => file.language === "rust").map((file) => file.relPath);
    expect(rust).toEqual(["src/main.rs"]);
    const loc = inv.files.find((file) => file.relPath === "src/main.rs")?.loc ?? 0;
    expect(loc).toBeGreaterThanOrEqual(3);
    expect(inv.languages.rust).toEqual({ files: 1, loc });
  });

  it("ships 38 rs- rules with metadata in both languages", () => {
    expect(rustRules).toHaveLength(38);
    for (const rule of rustRules) {
      expect(rule.languages).toEqual(["rust"]);
      expect(rule.owasp === undefined || /^A\d{2}:2021$/.test(rule.owasp)).toBe(true);
      expect(rule.title_zh).toBeTruthy();
      expect(rule.message_zh).toBeTruthy();
      expect(rule.remediation_zh).toBeTruthy();
      expect(rule.pathExclude).toBeTruthy();
      if (rule.kind === "hotspot") expect(rule.confidence).toBe("low");
    }
  });
});

describe("Rust fixtures", () => {
  const expected = loadExpected();
  const seeds = expected.seeds.filter((seed) => seed.language === "rust");

  it("reports exactly the seeds listed in EXPECTED.json under rust/", () => {
    const result = scanRules(inventory(VULNERABLE).files, ruleSet);
    const actual = result.hits
      .filter((hit) => hit.file.relPath.startsWith("rust/"))
      .map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}:${hit.rule.kind}`)
      .sort();
    const listed = seeds
      .map((seed) => `${seed.file}:${seed.line}:${seed.ruleId}:${seed.kind ?? "finding"}`)
      .sort();
    expect(actual).toEqual(listed);
    // Every rs- rule has a seed.
    const seeded = new Set(seeds.map((seed) => seed.ruleId));
    expect(rustRules.map((rule) => rule.id).filter((id) => !seeded.has(id))).toEqual([]);
  });

  it("reports no rs- result on the clean counterparts", () => {
    const result = scanRules(inventory(path.join(CLEAN, "rust")).files, ruleSet);
    expect(result.hits.map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}`)).toEqual([]);
  });

  it("masks hard-coded keys in every output file", async () => {
    const project = path.join(temp, "redact");
    writeFile(
      project,
      "src/keys.rs",
      [
        'static API_KEY: &str = "RustFixtureOnlyValueAbc123";',
        "pub fn key() -> jsonwebtoken::EncodingKey {",
        '    jsonwebtoken::EncodingKey::from_secret(b"RustFixtureJwtHmacXyz789")',
        "}",
        "",
      ].join("\n"),
    );
    const out = path.join(temp, "redact-out");
    const result = await scanProject({ root: project, out, offline: true, engines: ["builtin"], formats: ["md", "json", "sarif"] });
    const ruleIds = result.findings.map((finding) => finding.ruleId);
    expect(ruleIds).toContain("rs-hardcoded-secret");
    expect(ruleIds).toContain("rs-jwt-hardcoded-secret");
    const written = readAllOutputFiles(out);
    expect(written).not.toContain("RustFixtureOnlyValueAbc123");
    expect(written).not.toContain("RustFixtureJwtHmacXyz789");
  });
});

describe("Rust rules: safe variants and paths stay silent", () => {
  it("does not flag bind parameters, the query! macros or quoted identifiers", () => {
    expect(
      rustHits("src/db.rs", [
        "use sqlx::PgPool;",
        'let user = sqlx::query!("SELECT * FROM users WHERE id = $1", id).fetch_one(&pool).await?;',
        'let user = sqlx::query_as!(User, "SELECT * FROM users WHERE name = $1", name).fetch_one(&pool).await?;',
        'let rows = sqlx::query("SELECT * FROM users WHERE name = $1").bind(name).fetch_all(&pool).await?;',
        'conn.execute("INSERT INTO t (a) VALUES (?1)", params![a])?;',
        'conn.execute(&format!("CREATE DATABASE {}", quote_identifier(&name))).await?;',
        'let msg = format!("Select {} from the list", item);',
        'log::info!("{}", format!("update {} rows", n));',
        'qb.push_bind(name);',
        'qb.push(" AND name = ");',
      ]),
    ).toEqual([]);
  });

  it("flags SQL built with format!, + and push_str, and only the injected call once", () => {
    const hits = rustHits("src/db.rs", [
      "use sqlx::PgPool;",
      'sqlx::query(&format!("SELECT * FROM t WHERE a = {}", a)).execute(&pool).await?;',
      'client.query(&format!("select * from t where a = \'{}\'", a), &[]).await?;',
      'let q = format!("SELECT id FROM t WHERE name = \'{}\'", name);',
      "sql.push_str(&filter);",
      'conn.execute(&*format!("DROP TABLE {}", table)).await?;',
    ]);
    expect(hits).toEqual([
      "2:rs-sql-injection",
      "3:rs-sql-injection",
      "4:rs-sql-built-string",
      "5:rs-sql-built-string",
      "6:rs-sql-built-string",
    ]);
  });

  it("does not flag programs run without a shell or with a literal script", () => {
    expect(
      rustHits("src/exec.rs", [
        "use std::process::Command;",
        'Command::new("git").args(["-c", &config, "log"]).output()?;',
        'Command::new("tar").arg("xzf").arg(&archive).status()?;',
        'Command::new(env!("CARGO_BIN_EXE_tool")).status()?;',
        'Command::new(std::env::current_exe()?).status()?;',
      ]),
    ).toEqual([]);
    expect(ids(rustHits("src/exec.rs", ['Command::new("sh").args(["-c", "ls -l"]).status()?;']))).toEqual([
      "rs-command-shell-api",
    ]);
  });

  it("does not flag secure randomness (thread_rng, OsRng, rand::rng) for tokens", () => {
    expect(
      rustHits("src/token.rs", [
        "let token: String = thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect();",
        "let mut key = [0u8; 32]; OsRng.fill_bytes(&mut key);",
        "let session_id: u128 = rand::rng().random();",
        "let mut rng = SmallRng::seed_from_u64(7); let jitter = rng.gen_range(0..10);",
      ]),
    ).toEqual([]);
  });

  it("does not flag TLS, cookie and CORS settings that keep protection on", () => {
    expect(
      rustHits("src/net.rs", [
        "use actix_web::cookie::Cookie;",
        "let client = reqwest::Client::builder().danger_accept_invalid_certs(false).build()?;",
        "let client = reqwest::Client::builder().danger_accept_invalid_certs(config.insecure).build()?;",
        "builder.set_verify(SslVerifyMode::PEER);",
        'let cookie = Cookie::build("id", v).secure(true).http_only(true).same_site(SameSite::Strict).finish();',
        'let cors = Cors::default().allowed_origin("https://example.com");',
        "let layer = CorsLayer::permissive();",
        'return Redirect::to("/login");',
        "if cookie.same_site() == Some(SameSite::None) { warn(); }",
      ]),
    ).toEqual([]);
  });

  it("does not flag placeholder or non-secret constants, bcrypt cost 10+, or JWT keys from config", () => {
    expect(
      rustHits("src/auth.rs", [
        "use bcrypt;",
        'const TOKEN_HEADER: &str = "Authorization-Bearer";',
        'const API_KEY_ENV: &str = "SERVICE_API_KEY_VALUE";',
        'static PASSWORD: &str = "your-password-here";',
        'const SECRET: &str = "short";',
        "let hash = bcrypt::hash(password, 10)?;",
        "let hash = bcrypt::hash(password, DEFAULT_COST)?;",
        "let key = EncodingKey::from_secret(config.jwt_secret.as_bytes());",
        "validation.validate_exp = true;",
      ]),
    ).toEqual([]);
  });

  it("flags only the dangerous memory APIs, not every unsafe block", () => {
    expect(
      rustHits("src/mem.rs", [
        "unsafe { libc::getpid() }",
        "let value = unsafe { *ptr };",
        "let buf = MaybeUninit::<[u8; 16]>::uninit();",
        "static COUNTER: AtomicUsize = AtomicUsize::new(0);",
        "let x = values.get(i).copied();",
      ]),
    ).toEqual([]);
  });

  it("does not report a ReDoS rule for the linear-time regex crate", () => {
    expect(rustHits("src/re.rs", ['let re = Regex::new(&format!("(a+)+{}", user)).unwrap();'])).toEqual([]);
    expect(rustRules.some((rule) => rule.cwe === "CWE-1333")).toBe(false);
  });

  it("skips comment lines, including doc-test examples", () => {
    expect(
      rustHits("src/lib.rs", [
        '/// sqlx::query(&format!("SELECT * FROM t WHERE a = {}", a));',
        '//! Command::new("sh").arg("-c").arg(format!("ls {}", dir));',
        "// reqwest::Client::builder().danger_accept_invalid_certs(true)",
      ]),
    ).toEqual([]);
  });

  it("excludes tests/, benches/, examples/ and *_test.rs files", () => {
    const line = "let client = reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;";
    expect(rustHits("src/client.rs", [line])).toEqual(["1:rs-tls-accept-invalid"]);
    for (const relPath of [
      "tests/client.rs",
      "benches/bench.rs",
      "examples/client.rs",
      "crates/net/tests/it.rs",
      "src/client_test.rs",
      "src/tests.rs",
    ]) {
      expect(rustHits(relPath, [line]), relPath).toEqual([]);
    }
  });

  it("needs the zip, tar, web-framework or shell context for context-dependent rules", () => {
    // Without a zip / tar / web framework in the file, .name() / .path() / .unpack and
    // request-like names are ordinary code.
    expect(
      rustHits("src/plain.rs", [
        "let out = dir.join(self.name());",
        "let out = dir.join(entry.path());",
        "pkg.unpack(&dest)?;",
        "let data = fs::read(base.join(query.file))?;",
        'let out = Command::new("python").args(["-c", &code]).output()?;',
      ]),
    ).toEqual([]);
  });

  // rustfmt puts each link of a long method chain, and each argument of a
  // long call, on its own line; the C-family lexer joins both.
  it("rs-command-shell-injection: Command::new(\"sh\") / .arg(\"-c\") / .arg(cmd) on three lines", () => {
    expect(
      rustHits("src/run.rs", [
        "pub fn run(cmd: &str) {",
        '    let out = Command::new("sh")',
        '        .arg("-c")',
        "        .arg(cmd)",
        "        .output();",
        "}",
      ]),
    ).toEqual(["3:rs-command-shell-injection"]);
  });
  it("rs-sql-injection: sqlx::query(\\n &format!(...)\\n) split over lines", () => {
    expect(
      rustHits("src/db.rs", [
        "pub async fn find(pool: &PgPool, name: &str) {",
        "    let rows = sqlx::query(",
        '        &format!("SELECT * FROM users WHERE name = \'{}\'", name),',
        "    )",
        "    .fetch_all(pool)",
        "    .await;",
        "}",
      ]),
    ).toEqual(["2:rs-sql-injection"]);
  });
  it("all rules: no match inside /* */ block comments (also nested) and doc comments", () => {
    expect(
      rustHits("src/tls.rs", [
        "/* let c = reqwest::Client::builder().danger_accept_invalid_certs(true);",
        "   /* nested */ Command::new(\"sh\").arg(\"-c\").arg(cmd) */",
        "/// let c = builder.danger_accept_invalid_certs(true);",
        "fn f() {}",
      ]),
    ).toEqual([]);
  });
  it("API rules: no match that starts inside a string literal (codeOnly)", () => {
    expect(
      rustHits("src/docs.rs", [
        'const HELP: &str = "use Command::new(\\"sh\\").arg(\\"-c\\").arg(cmd) and .danger_accept_invalid_certs(true)";',
        'let code = r#"let k = mem::transmute::<u8, i8>(x); Cors::permissive()"#;',
        "let s = \"multi line",
        "    md5::compute(data) and SameSite::None\";",
      ]),
    ).toEqual([]);
    // The same calls as code are reported.
    expect(
      ids(rustHits("src/net.rs", ["let c = builder.danger_accept_invalid_certs(true);", "let l = Cors::permissive();"])),
    ).toEqual(["rs-tls-accept-invalid", "rs-cors-permissive"]);
  });
  it.todo("rs-cors-any-origin-credentials: credentials enabled in another file than the any-origin policy");
  it.todo("rs-path-traversal: Path(name) extractor bound in the signature and used on a later line (needs data flow)");
});

describe("Rust rules: review fixes", () => {
  it("classifies Rust test, bench and fuzz paths as test context", () => {
    for (const file of ["src/parser_test.rs", "src/tests.rs", "benches/parse.rs", "fuzz/fuzz_targets/a.rs", "tests/it.rs"]) {
      expect([file, classifyPath(file)]).toEqual([file, "test"]);
    }
    expect(classifyPath("src/fuzzy/match.rs")).toBeUndefined();
    expect(classifyPath("src/testing_utils.rs")).toBeUndefined();
  });

  it("excludes fuzz directories by whole segment only", () => {
    const line = "let c = reqwest::Client::builder().danger_accept_invalid_certs(true).build()?;";
    expect(rustHits("src/fuzzy/client.rs", [line])).toEqual(["1:rs-tls-accept-invalid"]);
    expect(rustHits("fuzz-targets/client.rs", [line])).toEqual([]);
    expect(rustHits("rustls-fuzzing-provider/src/lib.rs", [line])).toEqual([]);
  });

  it("reports SQL whose interpolations are identifiers as built-string hotspots, values as findings", () => {
    const hits = rustHits("src/db.rs", [
      "use sqlx;",
      'let stmt = tx.prepare_cached(&format!("SELECT id FROM {table_name} WHERE x = $1"))?;',
      'diesel::sql_query(format!("LISTEN {CHANNEL}")).execute(conn)?;',
      'sqlx::query(&format!("SET statement_timeout = {TIMEOUT_MS}")).execute(&pool).await?;',
      'conn.execute(&format!("DROP TABLE {}", name), [])?;',
      'conn.execute(&format!("vacuum main into \'{filename}\'"), [])?;',
      'sqlx::query(&format!("SELECT * FROM {schema}.{table}")).fetch_all(&p).await?;',
      'sqlx::query(&format!("SELECT * FROM {table} WHERE id = {id}")).fetch_all(&p).await?;',
      'let q = sql::<Bool>(&format!("name = \'{}\'", name));',
      'let e = Expr::cust(&format!("lower(name) = \'{}\'", n));',
      'sqlx::query(&format!("SELECT {{x}} FROM t WHERE a = {a}")).fetch_all(&p).await?;',
    ]);
    expect(hits).toEqual([
      "2:rs-sql-built-string",
      "3:rs-sql-built-string",
      "4:rs-sql-built-string",
      "5:rs-sql-built-string",
      "6:rs-sql-injection",
      "7:rs-sql-built-string",
      "8:rs-sql-injection",
      "9:rs-sql-injection",
      "10:rs-sql-injection",
      "11:rs-sql-injection",
    ]);
    // Vectors of statements are not SQL builders.
    expect(rustHits("src/gen.rs", ["stmts.push(buf);", "statements.push(stmt);", "query.push_str(&param);"])).toEqual([]);
    expect(ids(rustHits("src/gen.rs", ["sql.push_str(&filter);", "query_builder.push(name);"]))).toEqual([
      "rs-sql-built-string",
      "rs-sql-built-string",
    ]);
  });

  it("keeps non-secret constants out of rs-hardcoded-secret and still finds real ones", () => {
    expect(
      rustHits("src/k.rs", [
        'const TOKEN_ROUTE: &str = "/api/v3/configure/token";',
        'const API_TOKEN_BIND_ADDR: &str = "127.0.0.1:8080";',
        'const TOKEN_SERVER: &str = "auth.local:8443";',
        'const TOKEN: &str = "__NODE_VERSION__";',
        'const EXAMPLE_TOKEN: &str = "abcdefgh12345678";',
        'const TEST_SECRET: &str = "abcdefgh12345678";',
        'const NON_SEPARATOR_TOKENS_KEY: &str = "non-separator-tokens";',
        'const MEILI_MASTER_KEY: &str = "MEILI_MASTER_KEY";',
        'const DB_PASSWORD: &str = "password";',
        'const SECRET_STORE: &str = "https://vault.internal/v1";',
      ]),
    ).toEqual([]);
    expect(
      rustHits("src/k.rs", [
        'const JWT_SECRET: &str = "my_super_secret_key";',
        'const API_TOKEN: &str = "supersecrettoken";',
        'const AES_KEY: [u8; 16] = *b"0123456789abcdef";',
      ]),
    ).toEqual(["1:rs-hardcoded-secret", "2:rs-hardcoded-secret", "3:rs-hardcoded-secret"]);
  });

  it("matches ECB constructions, not ECB types", () => {
    expect(rustHits("src/c.rs", ["enum Mode { Aes128Ecb(Box<ecb::Encryptor<aes::Aes128>>) }"])).toEqual([]);
    expect(ids(rustHits("src/c.rs", ["let enc = ecb::Encryptor::<aes::Aes128>::new(key.into());"]))).toEqual(["rs-weak-cipher"]);
  });

  it("separates deliberate deterministic RNGs and word fragments from secret RNG use", () => {
    expect(
      rustHits("src/r.rs", [
        "let mut rng = ChaCha20Rng::from_seed(stable_hash(&input)); let key = rng.gen::<u64>();",
        "let footprint = SmallRng::seed_from_u64(1).gen::<u32>();",
        "let hotplug = fastrand::u64(..);",
      ]),
    ).toEqual([]);
    expect(
      ids(
        rustHits("src/r.rs", [
          "let mut rng = ChaCha20Rng::from_seed([0u8; 32]); let api_key = rng.gen::<u128>();",
          "let session_token: String = std::iter::repeat_with(fastrand::alphanumeric).take(32).collect();",
          "let otp = Pcg64::seed_from_u64(now).gen_range(0..999999);",
        ]),
      ),
    ).toEqual(["rs-insecure-rng-secret", "rs-insecure-rng-secret", "rs-insecure-rng-secret"]);
  });

  it("covers the session-middleware, struct and alternative-API forms", () => {
    expect(
      rustHits("src/w.rs", [
        "use tower_sessions::SessionManagerLayer;",
        "let layer = SessionManagerLayer::new(store).with_secure(false);",
        "let mw = SessionMiddleware::builder(store, key).cookie_http_only(false).build();",
        "let v = Validation { validate_exp: false, ..Default::default() };",
        "validation.required_spec_claims.clear();",
        'let k = DecodingKey::from_base64_secret("c2VjcmV0c2VjcmV0").unwrap();',
        "config.set_verify_hostname(false);",
        "return Redirect::temporary(&q.return_to);",
        "return Redirect::to(uri!(index));",
      ]),
    ).toEqual([
      "2:rs-cookie-insecure",
      "3:rs-cookie-insecure",
      "4:rs-jwt-exp-disabled",
      "5:rs-jwt-exp-disabled",
      "6:rs-jwt-hardcoded-secret",
      "7:rs-tls-accept-invalid",
      "8:rs-open-redirect",
    ]);
  });

  it("finds shell injection with -lc / -ec flags, &*cmd and the (shell, flag) idiom", () => {
    expect(
      rustHits("src/sh.rs", [
        "use std::process::Command;",
        'fn a() { Command::new("bash").args(["-lc", &script]).status(); }',
        'fn b() { Command::new("bash").arg("-ec").arg(&*cmd).status(); }',
        'fn c() { let (shell, flag) = if cfg!(windows) { ("cmd", "/C") } else { ("sh", "-c") }; }',
        "fn d() { Command::new(shell).arg(flag).arg(&cmd).status(); }",
      ]),
    ).toEqual(["2:rs-command-shell-injection", "3:rs-command-shell-injection", "5:rs-command-shell-injection"]);
  });

  it("follows common extractor bindings into file paths", () => {
    expect(
      rustHits("src/h.rs", [
        "use axum::extract::{Json, Query};",
        'async fn a(Query(q): Query<P>) { let f = File::open(format!("data/{}", q.name)); }',
        'async fn b(Json(body): Json<P>) { let p = PathBuf::from(format!("uploads/{}", body.file)); }',
        "async fn c(Json(body): Json<P>) { items.push(body.item); }",
      ]),
    ).toEqual(["2:rs-path-traversal", "3:rs-path-traversal"]);
  });

  it("does not treat send_wildcard or method hashes as findings", () => {
    expect(
      rustHits("src/m.rs", [
        "use bcrypt::verify;",
        "let cors = Cors::default().send_wildcard().supports_credentials();",
        "let h = argon2::hash(password, 4);",
        "value.hash(&mut hasher, 4);",
      ]),
    ).toEqual([]);
  });
});
