import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { inventory } from "../src/inventory.js";
import { loadRules, scanRules } from "../src/rules.js";
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

const temp = makeTempDir("rules-go");
afterAll(() => cleanup(temp));

const ruleSet = loadRules(RULES_DIR);
const goRules = ruleSet.rules.filter((rule) => rule.id.startsWith("go-"));

let caseCounter = 0;
/** Scan one Go file at `relPath` and return `line:ruleId` for every go- hit. */
function goHits(lines: string[], relPath = "app/handler.go"): string[] {
  caseCounter += 1;
  const project = path.join(temp, `case-${caseCounter}`);
  writeFile(project, relPath, `${lines.join("\n")}\n`);
  const result = scanRules(inventory(project).files, ruleSet);
  return result.hits
    .filter((hit) => hit.rule.id.startsWith("go-"))
    .map((hit) => `${hit.line}:${hit.rule.id}`);
}

/** Hits of one statement placed in a function body (line 2 of the file). */
function stmt(code: string, header: string[] = []): string[] {
  return goHits([...header, "func f() {", `\t${code}`, "}"]).map(
    (hit) => hit.split(":")[1] as string,
  );
}

const IMPORT_MATH_RAND = ["package main", "", 'import "math/rand"', ""];

describe("Go rule metadata", () => {
  it("ships 50 go- rules with metadata in both languages", () => {
    expect(goRules).toHaveLength(50);
    for (const rule of goRules) {
      expect(rule.sourceFile.endsWith(path.join("sast", "go.yml"))).toBe(true);
      expect(rule.languages).toEqual(["go"]);
      expect(rule.owasp).toMatch(/^A\d{2}:2021$/);
      expect(rule.title_zh).toBeTruthy();
      expect(rule.message_zh).toBeTruthy();
      expect(rule.remediation_zh).toBeTruthy();
      expect(rule.compiled.pathExclude?.test("pkg/handler_test.go")).toBe(true);
      expect(rule.compiled.pathExclude?.test("internal/testdata/x.go")).toBe(true);
      expect(rule.compiled.pathExclude?.test("vendor/github.com/x/y.go")).toBe(true);
      expect(rule.compiled.pathExclude?.test("pkg/handler.go")).toBe(false);
      if (rule.kind === "hotspot") expect(rule.confidence).toBe("low");
      if (rule.kind !== "hotspot") expect(rule.confidence).not.toBe("low");
    }
  });

  it("redacts every rule that matches a credential literal", () => {
    const redacted = goRules.filter((rule) => rule.redactEvidence).map((rule) => rule.id);
    expect(redacted.sort()).toEqual(["go-hardcoded-crypto-key", "go-jwt-hardcoded-secret"]);
  });
});

describe("Go fixtures", () => {
  const expected = loadExpected();
  const inScope = (file: string): boolean => /^(?:api\/)?go\//.test(file);

  it("reports exactly the go- seeds listed in EXPECTED.json, with their kinds", () => {
    const result = scanRules(inventory(VULNERABLE).files, ruleSet);
    const actual = result.hits
      .filter((hit) => inScope(hit.file.relPath))
      .map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}:${hit.rule.kind}`)
      .sort();
    const listed = expected.seeds
      .filter((seed) => seed.language === "go" && inScope(seed.file))
      .map((seed) => `${seed.file}:${seed.line}:${seed.ruleId}:${seed.kind ?? "finding"}`)
      .sort();
    expect(actual).toEqual(listed);
    // Every go- rule has at least one seed.
    const seeded = new Set(expected.seeds.map((seed) => seed.ruleId));
    expect(goRules.map((rule) => rule.id).filter((id) => !seeded.has(id))).toEqual([]);
  });

  it("finds no go- findings in the clean Go fixtures and at most low hotspots", () => {
    const result = scanRules(inventory(CLEAN).files, ruleSet);
    const goHitsClean = result.hits.filter(
      (hit) => hit.rule.id.startsWith("go-") || inScope(hit.file.relPath),
    );
    expect(goHitsClean.filter((hit) => hit.rule.kind === "finding")).toEqual([]);
    for (const hit of goHitsClean) expect(hit.rule.confidence).toBe("low");
    // The one tolerated hotspot: ORDER BY with a column picked from constants.
    // and a loopback-only pprof listener without timeouts.
    expect(goHitsClean.map((hit) => `${hit.file.relPath}:${hit.rule.id}`).sort()).toEqual([
      "go/pprof.go:go-http-server-no-timeout",
      "go/sqli.go:go-sql-api",
    ]);
  });

  it("never shows the hard-coded key or JWT secret in any output", async () => {
    const out = path.join(temp, "redaction-out");
    const result = await scanProject({
      root: path.join(VULNERABLE, "go"),
      out,
      offline: true,
      engines: ["builtin"],
      formats: ["json", "md", "sarif"],
    });
    const ids = new Set(result.findings.map((finding) => finding.ruleId));
    expect(ids.has("go-hardcoded-crypto-key")).toBe(true);
    expect(ids.has("go-jwt-hardcoded-secret")).toBe(true);
    const text = readAllOutputFiles(out);
    expect(text).not.toContain("Zq8vR2mT7xK4pL9w");
    expect(text).not.toContain("Hk3vQ9zP2mR7tX5w");
  });
});

describe("Go SQL rules", () => {
  it("separates request data in the SQL text from request data as a bind argument", () => {
    expect(stmt('db.Query("SELECT * FROM t WHERE a = \'" + r.FormValue("a") + "\'")')).toEqual([
      "go-sql-injection",
    ]);
    expect(stmt('db.Query("SELECT * FROM t WHERE a = $1", r.FormValue("a"))')).toEqual([]);
    expect(stmt('db.QueryContext(ctx, "SELECT * FROM t WHERE a = ?", c.Query("a"))')).toEqual([]);
    expect(stmt('dbx.Select(&out, "SELECT * FROM t WHERE a LIKE $1", "%"+c.Query("q")+"%")')).toEqual(
      [],
    );
    expect(stmt('gdb.Where("name = ?", c.Param("name")).Find(&users)')).toEqual([]);
    expect(stmt('gdb.Order(c.Query("sort")).Find(&users)')).toEqual(["go-sql-injection"]);
  });

  it("does not take a prepared statement's arguments or gin's c.Query for SQL", () => {
    expect(stmt('stmt.Exec(r.FormValue("id"))')).toEqual([]);
    expect(stmt('insertStmt.QueryRow(name)')).toEqual([]);
    expect(stmt('v := c.Query("page")')).toEqual([]);
    expect(stmt("q := r.URL.Query()")).toEqual([]);
  });

  it("reports a spliced comparison value at medium and ignores + inside the literal", () => {
    expect(stmt('db.Exec("UPDATE t SET locked = 1 WHERE login = \'" + login + "\'")')).toEqual([
      "go-sql-string-building",
    ]);
    expect(stmt('q := fmt.Sprintf("SELECT * FROM t WHERE owner = \'%s\'", owner)')).toEqual([
      "go-sql-string-building",
    ]);
    expect(stmt('db.Exec("UPDATE repo SET num_stars = num_stars + 1 WHERE id = ?", id)')).toEqual([]);
    expect(stmt('q := fmt.Sprintf("SELECT * FROM %s WHERE id IN (%s)", table, marks)')).toEqual([]);
    expect(stmt('db.Exec(fmt.Sprintf("DROP TABLE `%s`", table))')).toEqual([]);
  });

  it("keeps the API hotspot for runtime SQL text only", () => {
    expect(stmt("db.Query(query)")).toEqual(["go-sql-api"]);
    expect(stmt('db.Query("SELECT 1")')).toEqual([]);
    expect(stmt('db.ExecContext(ctx, "DELETE FROM t WHERE id = ?", id)')).toEqual([]);
    expect(stmt("db.Query(`SELECT 1`)")).toEqual([]);
    expect(goHits(["func f() {", "\tdb.Exec(sql)", "}"], "models/migrations/v1.go")).toEqual([]);
  });
});

describe("Go command and file rules", () => {
  it("grades exec.Command by what the statement shows", () => {
    expect(stmt('exec.Command("git", "log", r.URL.Query().Get("rev"))')).toEqual([
      "go-command-request",
    ]);
    expect(stmt('exec.Command("sh", "-c", "tar czf out.tgz "+dir)')).toEqual([
      "go-command-injection",
    ]);
    expect(stmt('exec.Command("sh", "-c", script)')).toEqual(["go-exec-shell"]);
    expect(stmt('exec.Command("sh", "-c", "ls -l")')).toEqual([]);
    expect(stmt('exec.Command("git", "status")')).toEqual([]);
    expect(stmt("exec.Command(tool, args...)")).toEqual(["go-exec-dynamic-program"]);
    expect(stmt('exec.Command(args[0], args[1:]...)')).toEqual(["go-exec-dynamic-program"]);
  });

  it("reports request data in a path unless only its base name is used", () => {
    expect(stmt('os.Open(filepath.Join(root, r.URL.Query().Get("f")))')).toEqual([
      "go-path-traversal",
    ]);
    expect(stmt('os.Open(filepath.Join(root, filepath.Base(r.URL.Query().Get("f"))))')).toEqual([]);
    expect(stmt('os.Open(filepath.Join(d, indexFilename))')).toEqual([]);
    expect(stmt('os.Open("/data/static.txt")')).toEqual([]);
    expect(stmt('os.Open(dir + "/" + name)')).toEqual(["go-path-api"]);
  });

  it("reports Zip Slip only when the file never checks the joined path", () => {
    const vulnerable = [
      "package main",
      'import "archive/zip"',
      "func x(dest string, f *zip.File) {",
      "\ttarget := filepath.Join(dest, f.Name)",
      "}",
    ];
    expect(goHits(vulnerable)).toEqual(["4:go-zip-slip"]);
    const checked = [
      ...vulnerable.slice(0, 4),
      "\tif !strings.HasPrefix(target, dest) { return }",
      "}",
    ];
    expect(goHits(checked)).toEqual([]);
    // os.File.Name() is a method call, not an archive entry name.
    expect(goHits(["package main", 'import "archive/tar"', "p := filepath.Join(dir, f.Name())"])).toEqual(
      [],
    );
  });

  it("separates world-writable modes from umask-reduced defaults", () => {
    expect(stmt('os.WriteFile("a.txt", data, 0777)')).toEqual(["go-file-permissions-api"]);
    expect(stmt('os.Chmod(path, 0o666)')).toEqual(["go-file-permissions"]);
    expect(stmt("os.MkdirAll(dir, 0o777)")).toEqual(["go-file-permissions-api"]);
    expect(stmt('os.WriteFile("a.txt", data, 0600)')).toEqual([]);
    expect(stmt("os.MkdirAll(dir, 0o750)")).toEqual([]);
  });

  it("reports fixed names under /tmp but not os.CreateTemp", () => {
    expect(stmt('os.Create("/tmp/report.csv")')).toEqual(["go-predictable-temp-file"]);
    expect(stmt('os.WriteFile(filepath.Join(os.TempDir(), "state.json"), b, 0600)')).toEqual([
      "go-predictable-temp-file",
    ]);
    expect(stmt('os.CreateTemp("", "report-*.csv")')).toEqual([]);
  });
});

describe("Go network, template and crypto rules", () => {
  it("separates SSRF and redirects from request data and constant URLs", () => {
    expect(stmt('http.Get(r.URL.Query().Get("u"))')).toEqual(["go-ssrf-request"]);
    expect(stmt("http.Get(target)")).toEqual(["go-ssrf"]);
    expect(stmt('http.Get("https://example.invalid/")')).toEqual([]);
    expect(stmt('http.Redirect(w, r, r.FormValue("next"), http.StatusFound)')).toEqual([
      "go-open-redirect",
    ]);
    expect(stmt('http.Redirect(w, r, "/home", http.StatusFound)')).toEqual([]);
  });

  it("reports TLS settings only when they weaken the connection", () => {
    expect(stmt("cfg := &tls.Config{InsecureSkipVerify: true}")).toEqual(["go-tls-disabled"]);
    expect(stmt("cfg := &tls.Config{InsecureSkipVerify: insecure}")).toEqual([]);
    expect(stmt("cfg := &tls.Config{MinVersion: tls.VersionTLS10}")).toEqual(["go-tls-min-version"]);
    expect(stmt("cfg := &tls.Config{MinVersion: tls.VersionTLS12}")).toEqual([]);
    expect(stmt("suites := []uint16{tls.TLS_RSA_WITH_RC4_128_SHA}")).toEqual(["go-tls-weak-cipher"]);
    expect(stmt('names := map[uint16]string{tls.TLS_RSA_WITH_RC4_128_SHA: "RC4"}')).toEqual([]);
  });

  it("separates template conversions of request data, runtime values and literals", () => {
    expect(stmt('v := template.HTML(r.FormValue("bio"))')).toEqual(["go-xss-template-request"]);
    expect(stmt("v := template.HTML(rendered)")).toEqual(["go-template-unescaped"]);
    expect(stmt('v := template.HTML("<br>")')).toEqual([]);
    expect(stmt('v := template.HTML("<div class=\\"alert\\">Bad password</div>")')).toEqual([]);
  });

  it("does not take jwt.Parse or url.Parse for template parsing", () => {
    const header = ["package main", 'import "text/template"'];
    expect(stmt('t, _ := template.New("x").Parse(r.FormValue("tpl"))', header)).toEqual([
      "go-template-injection",
    ]);
    expect(stmt('u, _ := url.Parse(r.FormValue("u"))', header)).toEqual([]);
    expect(stmt('tok, _ := jwt.Parse(r.Header.Get("Authorization"), keyFunc)', header)).toEqual([]);
  });

  it("reports math/rand only for secrets and only when math/rand is imported", () => {
    expect(stmt("token := rand.Int63()", IMPORT_MATH_RAND)).toEqual(["go-weak-random"]);
    expect(stmt("jitter := rand.Intn(100)", IMPORT_MATH_RAND)).toEqual([]);
    expect(stmt("token := rand.Read(buf)", ["package main", 'import "crypto/rand"'])).toEqual([]);
    expect(
      stmt("token := rand.Int63()", ["package main", 'import mrand "math/rand"']),
    ).toEqual([]);
  });

  it("checks RSA sizes, bcrypt costs and hashes of passwords", () => {
    expect(stmt("k, _ := rsa.GenerateKey(rand.Reader, 1024)")).toEqual(["go-rsa-weak-key"]);
    expect(stmt("k, _ := rsa.GenerateKey(rand.Reader, 2048)")).toEqual([]);
    expect(stmt("k, _ := rsa.GenerateKey(rand.Reader, 4096)")).toEqual([]);
    expect(stmt("h, _ := bcrypt.GenerateFromPassword(pw, 4)")).toEqual(["go-bcrypt-low-cost"]);
    expect(stmt("h, _ := bcrypt.GenerateFromPassword(pw, 12)")).toEqual([]);
    expect(stmt("h, _ := bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)")).toEqual([]);
    expect(stmt("sum := md5.Sum([]byte(password))")).toEqual(["go-weak-password-hash"]);
    expect(stmt("sum := md5.Sum(content)")).toEqual(["go-weak-hash"]);
    expect(stmt("mac := hmac.New(sha1.New, key)")).toEqual([]);
  });

  it("reports literal keys but not keys from the environment or placeholders", () => {
    expect(stmt('block, _ := aes.NewCipher([]byte("Zq8vR2mT7xK4pL9w"))')).toEqual([
      "go-hardcoded-crypto-key",
    ]);
    expect(stmt('block, _ := aes.NewCipher([]byte(os.Getenv("KEY")))')).toEqual([]);
    expect(stmt('key := []byte("your-key-here-000")')).toEqual([]);
    expect(stmt('s, _ := tok.SignedString([]byte("Hk3vQ9zP2mR7tX5w"))')).toEqual([
      "go-jwt-hardcoded-secret",
    ]);
    expect(stmt("s, _ := tok.SignedString(secret)")).toEqual([]);
    expect(stmt('const tokenHeader = "X-Auth-Token-Value"')).toEqual([]);
  });

  it("reports the none algorithm but not a comparison that rejects it", () => {
    expect(stmt("t := jwt.New(jwt.SigningMethodNone)")).toEqual(["go-jwt-none-alg"]);
    expect(stmt("if t.Method == jwt.SigningMethodNone { return }")).toEqual([]);
  });

  it("drops the jwt key-function hotspot when the same unit checks the method", () => {
    expect(
      stmt(
        "jwt.Parse(s, func(t *jwt.Token) (interface{}, error) { if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok { return nil, errBad }; return key, nil })",
      ),
    ).toEqual([]);
    expect(stmt("jwt.Parse(s, func(t *jwt.Token) (interface{}, error) {")).toEqual([
      "go-jwt-no-alg-check",
    ]);
  });
});

describe("Go web configuration rules", () => {
  it("needs both a wildcard origin and credentials in the file for CORS", () => {
    const base = ["package main", "var o = cors.Options{"];
    expect(goHits([...base, '\tAllowedOrigins: []string{"*"},', "\tAllowCredentials: true,", "}"])).toEqual([
      "4:go-cors-wildcard-credentials",
    ]);
    expect(
      goHits([...base, '\tAllowedOrigins: []string{"https://a.example"},', "\tAllowCredentials: true,", "}"]),
    ).toEqual([]);
    expect(goHits([...base, '\tAllowedOrigins: []string{"*"},', "}"])).toEqual([]);
  });

  it("reports insecure cookie flags only in files that build cookies", () => {
    expect(goHits(["package main", "c := &http.Cookie{Name: \"s\", Secure: false}"])).toEqual([
      "2:go-cookie-insecure",
    ]);
    expect(goHits(["package main", "cfg := Config{Secure: false}"])).toEqual([]);
    expect(stmt('c.SetCookie("s", v, 3600, "/", "", false, true)')).toEqual(["go-cookie-insecure"]);
    expect(stmt('c.SetCookie("s", v, 3600, "/", "", true, true)')).toEqual([]);
  });

  it("reports pprof only when the default mux is served", () => {
    const served = ["package main", 'import _ "net/http/pprof"', 'func main() { http.ListenAndServe(":6060", nil) }'];
    expect(goHits(served)).toEqual(["2:go-pprof-exposed", "3:go-http-server-no-timeout"]);
    const ownMux = ["package main", 'import _ "net/http/pprof"', 'func main() { http.ListenAndServe("127.0.0.1:6060", mux) }'];
    expect(goHits(ownMux)).toEqual(["3:go-http-server-no-timeout"]);
    const timeouts = ["package main", "srv := &http.Server{", "\tReadHeaderTimeout: 5 * time.Second,", "}"];
    expect(goHits(timeouts)).toEqual([]);
  });

  it("needs a decompressor in the file and no size limit for the bomb hotspot", () => {
    const base = ["package main", "gz, _ := gzip.NewReader(src)"];
    expect(goHits([...base, "io.Copy(dst, gz)"])).toEqual(["3:go-decompression-bomb"]);
    expect(goHits([...base, "io.Copy(dst, io.LimitReader(gz, 1<<20))"])).toEqual([]);
    expect(goHits(["package main", "io.Copy(dst, gz)"])).toEqual([]);
  });
});

describe("Go review fixes", () => {
  it("D1: finds request data in raw-string (backtick) SQL", () => {
    expect(stmt('db.Query(fmt.Sprintf(`SELECT * FROM t WHERE a = \'%s\'`, r.FormValue("a")))')).toEqual([
      "go-sql-injection",
    ]);
    expect(stmt('db.Exec(`DELETE FROM t WHERE id = ` + r.URL.Query().Get("id"))')).toEqual([
      "go-sql-injection",
    ]);
    expect(stmt("db.Query(`SELECT * FROM t WHERE a = '` + a + `'`)")).toEqual(["go-sql-string-building"]);
    expect(stmt('db.Query(`SELECT * FROM t WHERE a = $1`, r.FormValue("a"))')).toEqual([]);
  });

  it("D2: reports SSRF only for request data in the URL argument", () => {
    expect(stmt('http.Post("https://api.example.invalid/x", "text/plain", strings.NewReader(r.FormValue("b")))')).toEqual([]);
    expect(stmt('http.NewRequest("POST", "https://api.example.invalid/x", strings.NewReader(r.FormValue("b")))')).toEqual([]);
    expect(stmt('http.PostForm("https://api.example.invalid/x", url.Values{"q": {r.FormValue("q")}})')).toEqual([]);
    expect(stmt('item, _ := mc.Get(r.URL.Query().Get("key"))')).toEqual([]);
    expect(stmt('item, _ := cacheClient.Get(r.URL.Query().Get("key"))')).toEqual([]);
    expect(stmt('http.NewRequest("GET", r.FormValue("u"), nil)')).toEqual(["go-ssrf-request"]);
    expect(stmt('httpClient.Get(r.FormValue("u"))')).toEqual(["go-ssrf-request"]);
    expect(stmt('http.Get(fmt.Sprintf("http://%s/x", r.FormValue("h")))')).toEqual(["go-ssrf-request"]);
    expect(stmt('http.Get("http://" + host + "/x")')).toEqual(["go-ssrf"]);
    expect(stmt('http.Get(fmt.Sprintf("http://%s/x", host))')).toEqual(["go-ssrf"]);
  });

  it("D3: takes only the first argument of a file call for the path", () => {
    expect(stmt('os.WriteFile("/var/notes/a.txt", []byte(r.FormValue("note")), 0600)')).toEqual([]);
    expect(stmt('os.WriteFile(filepath.Join(dir, "a.txt"), []byte(r.FormValue("note")), 0600)')).toEqual([]);
    expect(stmt('os.WriteFile(filepath.Join(dir, r.FormValue("n")), data, 0600)')).toEqual([
      "go-path-traversal",
    ]);
    expect(stmt('os.Open(fmt.Sprintf("/srv/%s.txt", r.FormValue("n")))')).toEqual(["go-path-traversal"]);
    expect(stmt('os.Open(filepath.Join(base, filepath.Clean("/"+r.FormValue("n"))))')).toEqual([]);
  });

  it("D4/D5: accepts r.Context() and c.Request.Context() as the context argument", () => {
    expect(stmt('exec.CommandContext(r.Context(), "sh", "-c", "make "+target)')).toEqual([
      "go-command-injection",
    ]);
    expect(stmt('exec.CommandContext(c.Request.Context(), "bash", "-c", script)')).toEqual(["go-exec-shell"]);
    expect(stmt('exec.CommandContext(r.Context(), "git", "fetch", r.FormValue("remote"))')).toEqual([
      "go-command-request",
    ]);
    expect(stmt('pool.Query(r.Context(), "SELECT * FROM t WHERE a = $1", r.FormValue("a"))')).toEqual([]);
    expect(stmt('db.QueryContext(c.Request.Context(), "SELECT * FROM t WHERE a = $1", c.Query("a"))')).toEqual([]);
    expect(stmt('db.QueryContext(c.Request.Context(), q)')).toEqual(["go-sql-api"]);
  });

  it("D6: needs a JWT secret name that ends at secret/key", () => {
    for (const name of ["jwtKeyHeader", "signingKeyEnv", "jwtSecretPath", "signingKeyID", "AnonymousTokenSecret"]) {
      expect(stmt(`${name} := "value-that-is-long"`)).toEqual([]);
    }
    expect(stmt('jwtSecret := "Hk3vQ9zP2mR7tX5w"')).toEqual(["go-jwt-hardcoded-secret"]);
    expect(stmt('signingKey := []byte("Hk3vQ9zP2mR7tX5w")')).toEqual(["go-jwt-hardcoded-secret"]);
  });

  it("D7: ignores a defensive case jwt.SigningMethodNone", () => {
    expect(stmt("case jwt.SigningMethodNone:")).toEqual([]);
  });

  it("D8: reports bcrypt costs 4 to 9 only", () => {
    expect(stmt("h, _ := bcrypt.GenerateFromPassword(pw, 2)")).toEqual([]);
    expect(stmt("h, _ := bcrypt.GenerateFromPassword(pw, 9)")).toEqual(["go-bcrypt-low-cost"]);
    expect(stmt("h, _ := bcrypt.GenerateFromPassword(pw, bcrypt.MinCost)")).toEqual(["go-bcrypt-low-cost"]);
  });

  it("D9: exempts pprof on a loopback-only default mux", () => {
    for (const addr of ['"localhost:6060"', '"127.0.0.1:6060"', '"[::1]:6060"']) {
      const hits = goHits(["package main", 'import _ "net/http/pprof"', `func main() { http.ListenAndServe(${addr}, nil) }`]);
      expect(hits).toEqual(["3:go-http-server-no-timeout"]);
    }
  });

  it("D10: ignores escaped or sanitized request data in template conversions", () => {
    expect(stmt('v := template.HTML(html.EscapeString(r.FormValue("bio")))')).toEqual(["go-template-unescaped"]);
    expect(stmt('v := template.HTML(policy.Sanitize(r.FormValue("bio")))')).toEqual(["go-template-unescaped"]);
  });

  it("D11: separates secret names from counters and covers rand.Read(secret)", () => {
    expect(stmt("n := tokenCount + rand.Intn(5)", IMPORT_MATH_RAND)).toEqual([]);
    expect(stmt("retryTokens := rand.Intn(3)", IMPORT_MATH_RAND)).toEqual([]);
    expect(stmt("tokenBucket := rand.Intn(3)", IMPORT_MATH_RAND)).toEqual([]);
    expect(stmt("rand.Read(token)", IMPORT_MATH_RAND)).toEqual(["go-weak-random"]);
    expect(stmt("rand.Read(salt[:])", IMPORT_MATH_RAND)).toEqual(["go-weak-random"]);
    expect(stmt("rand.Read(buf)", IMPORT_MATH_RAND)).toEqual([]);
  });

  it("D12: an unrelated strings.HasPrefix does not hide Zip Slip", () => {
    const file = [
      "package main",
      'import "archive/zip"',
      "func x(dest string, f *zip.File) {",
      "	target := filepath.Join(dest, f.Name)",
      '	if strings.HasPrefix(line, "#") { return }',
      "}",
    ];
    expect(goHits(file)).toEqual(["4:go-zip-slip"]);
    const relChecked = [...file.slice(0, 4), "	rel, _ := filepath.Rel(dest, target)", "}"];
    expect(goHits(relChecked)).toEqual([]);
  });

  it("D14: does not treat a hashed reset token as a password hash", () => {
    expect(stmt("sum := sha256.Sum256([]byte(resetPasswordToken))")).toEqual([]);
    expect(stmt("sum := sha256.Sum256([]byte(password))")).toEqual(["go-weak-password-hash"]);
  });

  it("extends request sources to chi, echo, fiber, httprouter, PathValue and the Form map", () => {
    expect(stmt('os.ReadFile("/srv/" + chi.URLParam(r, "doc"))')).toEqual(["go-path-traversal"]);
    expect(stmt('os.Remove("/srv/" + r.PathValue("name"))')).toEqual(["go-path-traversal"]);
    expect(stmt('os.Open("/srv/" + ps.ByName("doc"))')).toEqual(["go-path-traversal"]);
    expect(stmt('exec.Command("rm", "/srv/cache/"+vars["key"])')).toEqual(["go-command-request"]);
    expect(stmt('return c.Redirect(c.Query("next"))')).toEqual(["go-open-redirect"]);
    expect(stmt('http.Redirect(w, r, r.Form["next"][0], http.StatusFound)')).toEqual(["go-open-redirect"]);
  });

  it("covers more shells and template.New(..).Funcs(..).Parse", () => {
    expect(stmt('exec.Command("bash", "-lc", line)')).toEqual(["go-exec-shell"]);
    expect(stmt('exec.Command("/usr/bin/env", "bash", "-c", line)')).toEqual(["go-exec-shell"]);
    expect(stmt('exec.Command(os.Getenv("SHELL"), "-c", line)')).toEqual(["go-exec-shell"]);
    expect(stmt('exec.Command("bash", "-lc", "make all")')).toEqual([]);
    const header = ["package main", 'import "text/template"'];
    expect(
      stmt('t, _ := template.New("p").Funcs(template.FuncMap{"u": strings.ToUpper}).Parse(r.FormValue("b"))', header),
    ).toEqual(["go-template-injection"]);
  });

  it("reports reflected request data in the response body", () => {
    expect(stmt('w.Write([]byte(r.URL.Query().Get("msg")))')).toEqual(["go-xss-response-write"]);
    expect(stmt('fmt.Fprintf(w, "<p>%s</p>", r.FormValue("n"))')).toEqual(["go-xss-response-write"]);
    expect(stmt('fmt.Fprintf(w, "count=%s", r.FormValue("n"))')).toEqual([]);
    expect(stmt('w.Write([]byte(html.EscapeString(r.FormValue("n"))))')).toEqual([]);
  });

  it("splits CORS: AllowOriginFunc returning true is a finding, a wildcard a hotspot", () => {
    const head = ["package main", "var o = cors.Options{"];
    expect(goHits([...head, "	AllowOriginFunc: func(o string) bool { return true },", "	AllowCredentials: true,", "}"])).toEqual([
      "4:go-cors-credentials-any-origin",
    ]);
    expect(goHits([...head, "	AllowAllOrigins: true,", "	AllowCredentials: true,", "}"])).toEqual([
      "4:go-cors-wildcard-credentials",
    ]);
  });
});

describe("Go test, testdata and vendor paths", () => {
  const code = ["package main", "func f() {", '\tdb.Query("SELECT * FROM t WHERE a = \'" + r.FormValue("a") + "\'")', "}"];

  it("reports the same code in a regular file", () => {
    expect(goHits(code, "pkg/handler.go")).toEqual(["3:go-sql-injection"]);
  });

  it("does not report it in _test.go, testdata/ or vendor/", () => {
    expect(goHits(code, "pkg/handler_test.go")).toEqual([]);
    expect(goHits(code, "pkg/testdata/handler.go")).toEqual([]);
    expect(goHits(code, "vendor/github.com/acme/db/handler.go")).toEqual([]);
  });

  it("matches only string-literal-free contexts where the rule says so", () => {
    // A string that only mentions a dangerous call is not a call.
    expect(stmt('log.Print("never call exec.Command(\\"sh\\", \\"-c\\", x+y)")')).toEqual([]);
  });

  it.todo(
    "ignores a dangerous call inside a // or /* */ comment (needs the C-family lexer; today the engine matches comment lines)",
  );
  it.todo(
    "sees a db.Query / jwt.Parse / fmt.Sprintf call split over several lines as one unit (needs the C-family lexer)",
  );
});
