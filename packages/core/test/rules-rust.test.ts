import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { inventory } from "../src/inventory.js";
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
      "6:rs-sql-injection",
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

  // The engine matches one physical line. rustfmt puts each link of a long
  // method chain, and each argument of a long call, on its own line; the
  // planned C-family lexer joins lines only while ( or [ are open.
  it.todo("rs-command-shell-injection: Command::new(\"sh\") / .arg(\"-c\") / .arg(cmd) on three lines (needs chain joining)");
  it.todo("rs-sql-injection: sqlx::query(\\n &format!(...)\\n) split over lines (fixed by the lexer joining open brackets)");
  it.todo("rs-cors-any-origin-credentials: credentials enabled in another file than the any-origin policy");
  it.todo("rs-path-traversal: Path(name) extractor bound in the signature and used on a later line (needs data flow)");
  it.todo("all rules: matches inside /* */ block comments and string literals (fixed by the lexer)");
});
