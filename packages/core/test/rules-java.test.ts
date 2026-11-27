/**
 * Java and Spring Boot rules (rules/sast/java.yml).
 *
 * - The seeds under fixtures/vulnerable/java (and api/java) and EXPECTED.json
 *   agree in both directions: every listed seed is reported and nothing else.
 * - The clean counterparts yield no finding of any kind, only low hotspots.
 * - Negative cases for the rules that look noisy: literals, constants, bound
 *   parameters, sanitised values, hardened factories and test paths.
 */
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

const temp = makeTempDir("rules-java");
afterAll(() => cleanup(temp));

const ruleSet = loadRules(RULES_DIR);
const javaRules = ruleSet.rules.filter((rule) => rule.id.startsWith("java-"));

const inScope = (relPath: string): boolean => /^(?:api\/)?java\//.test(relPath);

let counter = 0;
/** Scan one file (relative path, content) and return `line:ruleId` hits. */
function hits(relPath: string, lines: string[]): string[] {
  counter += 1;
  const root = path.join(temp, `case-${counter}`);
  writeFile(root, relPath, `${lines.join("\n")}\n`);
  const result = scanRules(inventory(root).files, ruleSet);
  return result.hits
    .filter((hit) => hit.rule.id.startsWith("java-"))
    .map((hit) => `${hit.line}:${hit.rule.id}`)
    .sort();
}

/** One Java statement inside a method of a class, scanned at line 3. */
function stmt(code: string, relPath = "src/main/java/App.java", header: string[] = []): string[] {
  return hits(relPath, [...header, "class App {", "  void m() throws Exception {", `    ${code}`, "  }", "}"]).map(
    (hit) => hit.replace(/^(\d+):/, (_, line: string) => `${Number(line) - header.length}:`),
  );
}

describe("java rule metadata", () => {
  it("has 70+ Java rules with bilingual texts, CWE, OWASP and case-sensitive matching", () => {
    expect(javaRules.length).toBeGreaterThanOrEqual(70);
    for (const rule of javaRules) {
      expect(rule.cwe).toMatch(/^CWE-\d+$/);
      expect(rule.owasp).toMatch(/^A\d{2}:2021$/);
      expect(rule.title_zh).toBeTruthy();
      expect(rule.message_zh).toBeTruthy();
      expect(rule.remediation_zh).toBeTruthy();
      if (rule.kind === "hotspot") expect(rule.confidence).toBe("low");
    }
  });

  it("marks every rule that matches a credential literal for redaction", () => {
    for (const id of ["java-hardcoded-crypto-key", "java-jwt-hardcoded-secret", "java-spring-datasource-password"]) {
      expect(javaRules.find((rule) => rule.id === id)?.redactEvidence, id).toBe(true);
    }
  });
});

describe("java fixtures", () => {
  it("reports exactly the EXPECTED.json seeds in the Java fixtures", () => {
    const expected = loadExpected().seeds.filter((seed) => inScope(seed.file));
    const result = scanRules(inventory(VULNERABLE).files, ruleSet);
    const actual = result.hits
      .filter((hit) => inScope(hit.file.relPath))
      .map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}:${hit.rule.kind ?? "finding"}`)
      .sort();
    const listed = expected
      .map((seed) => `${seed.file}:${seed.line}:${seed.ruleId}:${seed.kind ?? "finding"}`)
      .sort();
    expect(actual).toEqual(listed);
    // Every Java rule has a seed in the Java fixtures.
    const seeded = new Set(expected.map((seed) => seed.ruleId));
    expect(javaRules.map((rule) => rule.id).filter((id) => !seeded.has(id))).toEqual([]);
  });

  it("finds nothing but low hotspots in the clean Java fixtures", () => {
    const result = scanRules(inventory(path.join(CLEAN, "java")).files, ruleSet);
    const findings = result.hits.filter((hit) => (hit.rule.kind ?? "finding") === "finding");
    expect(findings.map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}`)).toEqual([]);
    for (const hit of result.hits) expect(hit.rule.confidence).toBe("low");
  });
});

describe("java SQL rules", () => {
  it("separates request data, value concatenation, identifiers and constants", () => {
    expect(stmt('st.executeQuery("SELECT * FROM t WHERE a = \'" + request.getParameter("a") + "\'");')).toEqual([
      "3:java-sql-injection-request",
    ]);
    expect(stmt('st.executeQuery("SELECT * FROM t WHERE a = " + a);')).toEqual(["3:java-sql-injection"]);
    expect(stmt('jdbc.query(String.format("SELECT * FROM t WHERE a = \'%s\'", a), mapper);')).toEqual([
      "3:java-sql-injection",
    ]);
    // Identifier position: hotspot only.
    expect(stmt('st.executeQuery("SELECT id FROM " + table + " WHERE x = ?");')).toEqual(["3:java-sql-concat-api"]);
    // Upper-case constants are not run-time values.
    expect(stmt('st.executeQuery("SELECT * FROM " + TABLE + " WHERE a = " + Cols.ID);')).toEqual([]);
    expect(stmt('String sql = "SELECT * FROM t WHERE name = \'" + name + "\'";')).toEqual(["3:java-sql-string-concat"]);
  });

  it("ignores bound parameters, literals and concatenation in later arguments", () => {
    expect(stmt('jdbc.queryForList("SELECT n FROM p WHERE n LIKE ?", String.class, "%" + term + "%");')).toEqual([]);
    expect(stmt('jdbc.query("SELECT * FROM t WHERE id = ?", mapper, request.getParameter("id"));')).toEqual([]);
    expect(stmt('st.executeQuery("SELECT 1");')).toEqual([]);
    expect(stmt("ps.executeQuery();")).toEqual([]);
    expect(stmt('st.executeQuery("SELECT * FROM t WHERE a = \'" + StringEscapeUtils.escapeSql(a) + "\'");')).toEqual([]);
    // CLI-style execute() of a non-SQL string is not SQL.
    expect(stmt('execute("create --config \'" + file + "\' -o");')).toEqual([]);
    expect(stmt("executor.execute(() -> run(a + b));")).toEqual([]);
  });

  it("flags MyBatis ${} but not #{}", () => {
    expect(stmt('@Select("SELECT * FROM u WHERE n = \'${name}\'")')).toEqual(["3:java-mybatis-dollar-substitution"]);
    expect(stmt('@Select("SELECT * FROM u WHERE n = #{name}")')).toEqual([]);
  });

  it("does not report SQL rules in test trees", () => {
    expect(stmt('st.executeQuery("SELECT * FROM t WHERE a = " + a);', "src/test/java/AppTest.java")).toEqual([]);
  });

  it.todo("ignores SQL concatenation inside a // comment (needs the planned C-family lexer)");
  it.todo("sees a concatenation passed to executeQuery on the next line (needs statement joining)");
});

describe("java command, expression and path rules", () => {
  it("distinguishes request data, concatenation, shell wrappers and literals", () => {
    expect(stmt('Runtime.getRuntime().exec("ping " + request.getParameter("h"));')).toEqual([
      "3:java-command-injection-request",
    ]);
    expect(stmt("r.exec(cmd + bar);")).toEqual(["3:java-command-injection"]);
    expect(stmt('new ProcessBuilder("sh", "-c", script).start();')).toEqual(["3:java-command-shell-wrapper"]);
    expect(stmt('new ProcessBuilder("sh", "-c", "ls -l /tmp").start();')).toEqual([]);
    expect(stmt('new ProcessBuilder("git", "status").start();')).toEqual([]);
    expect(stmt('Runtime.getRuntime().exec("uptime");')).toEqual([]);
  });

  it("only flags SpEL with a non-literal expression", () => {
    expect(stmt('parser.parseExpression("price * qty").getValue();')).toEqual([]);
    expect(stmt("parser.parseExpression(expr).getValue();")).toEqual(["3:java-expression-eval-api"]);
  });

  it("does not treat XPath evaluate as expression injection", () => {
    expect(stmt('xpath.evaluate(request.getParameter("q"), doc);')).toEqual([]);
  });

  it("keeps File hotspots to run-time paths", () => {
    expect(stmt('new File("/etc/app.conf");')).toEqual([]);
    expect(stmt("new java.io.File(Utils.TESTFILES_DIR);")).toEqual([]);
    expect(stmt("new File(dir, name);")).toEqual(["3:java-file-api"]);
    expect(stmt("new File(base, file.getName());")).toEqual(["3:java-file-api"]);
  });

  it("accepts a sanitised upload name and a checked zip entry", () => {
    expect(stmt("file.transferTo(dir.resolve(FilenameUtils.getName(file.getOriginalFilename())));")).toEqual([]);
    expect(stmt("file.transferTo(dir.resolve(UUID.randomUUID() + file.getOriginalFilename()));")).toEqual([]);
    expect(
      hits("src/main/java/Unzip.java", [
        "class Unzip {",
        "  void m() {",
        "    Path out = dest.resolve(entry.getName()).normalize();",
        "    if (!out.startsWith(dest)) throw new SecurityException();",
        "  }",
        "}",
      ]),
    ).toEqual([]);
  });
});

describe("java redirect and XSS rules", () => {
  it("ignores context-path redirects and fixed redirect prefixes", () => {
    expect(stmt('response.sendRedirect(request.getContextPath() + "/home");')).toEqual([]);
    expect(stmt('response.sendRedirect("/login");')).toEqual([]);
    expect(
      hits("src/main/java/C.java", [
        "class C {",
        '  String m(@RequestParam("id") long id) {',
        '    return "redirect:/orders/" + id;',
        "  }",
        "}",
      ]),
    ).toEqual([]);
  });

  it("only reports redirect: + variable in handlers that read parameters", () => {
    expect(stmt('return "redirect:" + target;')).toEqual([]);
    expect(stmt('return "redirect:" + target;', "src/main/java/App.java", ["class H { String h(@RequestParam String t) { return t; } }"])).toEqual([
      "3:java-open-redirect",
    ]);
  });

  it("accepts encoded output", () => {
    expect(stmt('response.getWriter().println(Encode.forHtml(request.getParameter("n")));')).toEqual([]);
    expect(stmt('response.getWriter().println(request.getParameter("n"));')).toEqual(["3:java-xss-request"]);
  });
});

describe("java deserialization and XML rules", () => {
  it("drops the XXE rules once the file hardens the factory", () => {
    const hardened = hits("src/main/java/Xml.java", [
      "class Xml {",
      "  void m() throws Exception {",
      "    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();",
      '    dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);',
      "    XMLInputFactory xif = XMLInputFactory.newInstance();",
      "    xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);",
      "  }",
      "}",
    ]);
    expect(hardened).toEqual([]);
    expect(stmt("DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();")).toEqual(["3:java-xxe"]);
  });

  it("drops ObjectInputStream when the file sets a filter, SnakeYAML with SafeConstructor", () => {
    expect(
      hits("src/main/java/In.java", [
        "class In {",
        "  Object m(InputStream in) throws Exception {",
        "    ObjectInputStream ois = new ObjectInputStream(in);",
        "    ois.setObjectInputFilter(FILTER);",
        "    return ois.readObject();",
        "  }",
        "}",
      ]),
    ).toEqual([]);
    expect(stmt("Object o = new Yaml(new SafeConstructor(new LoaderOptions())).load(text);")).toEqual([]);
    expect(stmt("Object o = new Yaml().load(text);")).toEqual(["3:java-snakeyaml-unsafe-load"]);
  });

  it("does not flag a safe Jackson polymorphic setup", () => {
    expect(stmt("mapper.activateDefaultTyping(BasicPolymorphicTypeValidator.builder().build());")).toEqual([]);
    expect(stmt("@JsonTypeInfo(use = JsonTypeInfo.Id.NAME)")).toEqual([]);
  });
});

describe("java crypto, TLS and JWT rules", () => {
  it("separates weak and strong algorithms", () => {
    expect(stmt('Cipher c = Cipher.getInstance("AES/GCM/NoPadding");')).toEqual([]);
    expect(stmt('Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");')).toEqual([]);
    expect(stmt('Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");')).toEqual(["3:java-weak-cipher"]);
    expect(stmt('Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");')).toEqual(["3:java-cipher-ecb"]);
    expect(stmt('MessageDigest d = MessageDigest.getInstance("SHA-256");')).toEqual([]);
  });

  it("checks iteration counts and bcrypt strength", () => {
    expect(stmt("new PBEKeySpec(pw, salt, 310000, 256);")).toEqual([]);
    expect(stmt("new PBEKeySpec(pw, salt, ITERATIONS, 256);")).toEqual([]);
    expect(stmt("new PBEKeySpec(pw, salt, 5000, 256);")).toEqual(["3:java-pbkdf-low-iterations"]);
    expect(stmt("new BCryptPasswordEncoder(12);")).toEqual([]);
    expect(stmt("new BCryptPasswordEncoder(10, random);")).toEqual([]);
  });

  it("only reports weak random values that are named like secrets", () => {
    expect(stmt("int jitter = ThreadLocalRandom.current().nextInt(100);")).toEqual([]);
    expect(stmt("String token = RandomStringUtils.randomAlphanumeric(32);")).toEqual(["3:java-weak-random-token"]);
  });

  it("accepts a TrustManager that rejects certificates and TLS 1.2+", () => {
    const tm = hits("src/main/java/Tm.java", [
      "class Tm implements X509TrustManager {",
      "  public void checkServerTrusted(X509Certificate[] chain, String type) throws CertificateException {",
      "    if (chain.length == 0) throw new CertificateException(\"empty\");",
      "  }",
      "}",
    ]);
    expect(tm).toEqual([]);
    expect(stmt('SSLContext ctx = SSLContext.getInstance("TLSv1.2");')).toEqual([]);
    expect(stmt('SSLContext ctx = SSLContext.getInstance("TLSv1.1");')).toEqual(["3:java-weak-tls-protocol"]);
    expect(stmt("import org.apache.http.conn.ssl.NoopHostnameVerifier;")).toEqual([]);
  });

  it("does not flag signed JWT parsing or keys from configuration", () => {
    expect(stmt("Jwts.parserBuilder().setSigningKey(key).build().parseClaimsJws(token);")).toEqual([]);
    expect(stmt("Jwts.builder().signWith(key, SignatureAlgorithm.HS256).compact();")).toEqual([]);
    expect(stmt('Algorithm a = Algorithm.HMAC256(props.getSecret());')).toEqual([]);
  });

  it("reports cookie flags only when explicitly false", () => {
    expect(stmt("cookie.setSecure(true);", "src/main/java/App.java", ["import javax.servlet.http.Cookie;"])).toEqual([]);
    expect(stmt("cookie.setSecure(false);", "src/main/java/App.java", ["import javax.servlet.http.Cookie;"])).toEqual([
      "3:java-cookie-insecure-flag",
    ]);
  });
});

describe("java Spring Security rules", () => {
  it("keeps CSRF disable a hotspot for stateless APIs", () => {
    const api = hits("src/main/java/Api.java", [
      "class Api {",
      "  void m(HttpSecurity http) throws Exception {",
      "    http.csrf(csrf -> csrf.disable());",
      "    http.sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS));",
      "  }",
      "}",
    ]);
    expect(api).toEqual(["3:java-spring-csrf-disabled"]);
  });

  it("does not flag explicit origins or permitAll on specific paths", () => {
    expect(stmt('config.setAllowedOrigins(List.of("https://app.example.com"));')).toEqual([]);
    expect(stmt('auth.requestMatchers("/public/**").permitAll();')).toEqual([]);
    expect(stmt('@CrossOrigin(origins = "https://app.example.com")')).toEqual([]);
  });
});

describe("Spring Boot configuration rules", () => {
  const yml = (relPath: string, lines: string[]): string[] => hits(relPath, lines);

  it("ignores placeholders, safe exposure lists and dev profiles", () => {
    expect(
      yml("src/main/resources/application.yml", [
        "spring:",
        "  datasource:",
        "    password: ${DB_PASSWORD}",
        "management:",
        "  endpoints:",
        "    web:",
        "      exposure:",
        "        include: health,info",
      ]),
    ).toEqual([]);
    expect(
      yml("src/main/resources/application-dev.yml", [
        "spring:",
        "  datasource:",
        "    password: devpass123",
        "  h2.console.enabled: true",
      ]),
    ).toEqual([]);
  });

  it("only reads Spring configuration files", () => {
    expect(yml("deploy/values.yml", ["datasource: x", "password: Real-Looking-Pass-1"])).toEqual([]);
    expect(yml("src/main/resources/application.yml", ["datasource: x", "password: Real-Looking-Pass-1"])).toEqual([
      "2:java-spring-datasource-password",
    ]);
  });
});

describe("review fixes (fa1c8ab follow-up)", () => {
  it("1: does not flag Spring Security's allowlisting SecurityJackson2Modules.enableDefaultTyping", () => {
    expect(stmt("SecurityJackson2Modules.enableDefaultTyping(mapper);")).toEqual([]);
    expect(stmt("mapper.enableDefaultTyping();")).toEqual(["3:java-jackson-default-typing"]);
  });

  it("2: path traversal uses path-like request values and stays inside the call", () => {
    expect(stmt("Files.copy(request.getInputStream(), target);")).toEqual([]);
    expect(stmt('if (new File(baseDir, "x").exists() && request.getParameter("a") != null) {')).toEqual(["3:java-file-api"]);
    expect(stmt("URI next = uri.resolve(request.getRequestURI());")).toEqual([]);
    expect(stmt('Files.write(target, request.getParameter("body").getBytes());')).toEqual([]);
    expect(stmt('new File(base, URLDecoder.decode(request.getParameter("f"), "UTF-8"));')).toEqual([
      "3:java-path-traversal",
    ]);
    expect(stmt('Files.readAllBytes(Paths.get(root, request.getParameter("doc")));')).toEqual(["3:java-path-traversal"]);
  });

  it("2: request rules do not run past the closing parenthesis of their sink", () => {
    expect(stmt('rt.exec(cmd); audit(request.getParameter("u"));')).toEqual(["3:java-exec-api"]);
    expect(stmt('response.getWriter().write(page()); log(request.getParameter("q"));')).toEqual([]);
    expect(stmt('Class.forName(DRIVER).newInstance(); use(request.getParameter("t"));')).toEqual([]);
    expect(
      stmt('LOG.info("start"); handle(request.getParameter("u"));', "src/main/java/App.java", [
        "import org.apache.logging.log4j.Logger;",
      ]),
    ).toEqual([]);
    expect(
      stmt('engine.eval(script); bind(request.getParameter("x"));', "src/main/java/App.java", [
        "import javax.script.ScriptEngine;",
      ]),
    ).toEqual(["3:java-expression-eval-api"]);
  });

  it("3: expression injection needs an expression or script engine in the file", () => {
    expect(stmt('policy.evaluate(request.getParameter("role"));')).toEqual([]);
    expect(stmt('rules.eval(request.getParameter("x"));')).toEqual([]);
    expect(
      stmt('engine.eval(request.getParameter("x"));', "src/main/java/App.java", ["import javax.script.ScriptEngine;"]),
    ).toEqual(["3:java-expression-injection-request"]);
  });

  it("4: command concatenation must be inside the ProcessBuilder / exec call", () => {
    expect(stmt("new ProcessBuilder(cmd).directory(new File(base + sub)).start();")).toEqual([
      "3:java-exec-api",
      "3:java-file-api",
    ]);
    expect(stmt('new ProcessBuilder("tar", "-xf", archive + suffix).start();')).toEqual(["3:java-command-injection"]);
  });

  it("5: service passwords in Spring config, but not Jasypt ENC() or Spring Cloud {cipher}", () => {
    const conf = (value: string): string[] =>
      hits("src/main/resources/application.yml", ["spring:", "  rabbitmq:", `    password: ${value}`]);
    expect(conf("Real-Looking-Rabbit-1")).toEqual(["3:java-spring-datasource-password"]);
    expect(conf("ENC(AbCdEfGh123456)")).toEqual([]);
    expect(conf("'{cipher}AbCdEf0123'")).toEqual([]);
    expect(conf("${RABBIT_PASSWORD}")).toEqual([]);
    expect(hits("src/main/resources/application.yml", ["server:", "  ssl:", "    key-store-password: changeit"])).toEqual([]);
  });

  it("6: jjwt 0.12 verifyWith/decryptWith/keyLocator parsers are safe unless unsecured()", () => {
    expect(stmt("Jwts.parser().verifyWith(key).build().parse(token);")).toEqual([]);
    expect(stmt("Jwts.parser().keyLocator(locator).build().parse(token);")).toEqual([]);
    expect(stmt("Jwts.parser().decryptWith(key).build().parse(token);")).toEqual([]);
    expect(stmt("Jwts.parser().unsecured().verifyWith(key).build().parse(token);")).toEqual([
      "3:java-jwt-unsigned-parse",
    ]);
    expect(stmt("Jwts.parser().setSigningKey(KEY).parse(token);")).toEqual(["3:java-jwt-unsigned-parse"]);
  });

  it("7: finds the H2 console in the nested YAML form, not when disabled", () => {
    const nested = (value: string): string[] =>
      hits("src/main/resources/application.yml", ["spring:", "  h2:", "    console:", `      enabled: ${value}`, "      path: /h2"]);
    expect(nested("true")).toEqual(["4:java-spring-h2-console"]);
    expect(nested("false")).toEqual([]);
    expect(hits("src/main/resources/application.yml", ["spring:", "  h2.console.enabled: true"])).toEqual([
      "2:java-spring-h2-console",
    ]);
  });

  it.todo("7: application*.properties variants of the Spring Boot rules (needs a properties language in the engine)");

  it("8: MyBatis ${} in the array form and dynamic SQL fallbacks", () => {
    expect(stmt('@Select({"<script>", "SELECT * FROM u", "WHERE n = \'${name}\'", "</script>"})')).toEqual([
      "3:java-mybatis-dollar-substitution",
    ]);
    expect(stmt('@Select({"<script>", "SELECT * FROM u WHERE n = #{name}", "</script>"})')).toEqual([]);
    expect(stmt("jdbcTemplate.queryForList(sql);")).toEqual(["3:java-sql-api"]);
    expect(stmt("em.createQuery(jpql);")).toEqual(["3:java-sql-api"]);
    expect(stmt("em.createQuery(criteriaQuery);")).toEqual([]);
    expect(stmt("conn.createStatement().execute(sql);")).toEqual(["3:java-sql-api"]);
    expect(stmt('jdbcTemplate.queryForObject("SELECT 1", Integer.class);')).toEqual([]);
  });

  it("9: only SQL-aware escaping removes a SQL finding", () => {
    expect(stmt('st.executeQuery("SELECT * FROM t WHERE a = \'" + StringEscapeUtils.escapeHtml4(a) + "\'");')).toEqual([
      "3:java-sql-injection",
    ]);
    expect(stmt('st.executeQuery("SELECT * FROM t WHERE a = \'" + ESAPI.encoder().encodeForSQL(codec, a) + "\'");')).toEqual([]);
  });

  it("calibration: SQL concatenation at the sink is high confidence; dev profiles skip actuator", () => {
    expect(javaRules.find((rule) => rule.id === "java-sql-injection")?.confidence).toBe("high");
    expect(
      hits("src/main/resources/application-dev.yml", [
        "management:",
        "  endpoints:",
        "    web:",
        "      exposure:",
        '        include: "*"',
      ]),
    ).toEqual([]);
  });
});
