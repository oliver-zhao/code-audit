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

const temp = makeTempDir("rules-cpp");
afterAll(() => cleanup(temp));

const ruleSet = loadRules(RULES_DIR);
const cppRules = ruleSet.rules.filter((rule) => rule.id.startsWith("cpp-"));

let projectCounter = 0;

/** Scan one C or C++ source and return `line:ruleId` for every cpp- hit. */
function hitsOf(source: string, fileName = "src/sample.c"): string[] {
  projectCounter += 1;
  const root = path.join(temp, `p${projectCounter}`);
  writeFile(root, fileName, `${source}\n`);
  const result = scanRules(inventory(root).files, ruleSet);
  return result.hits
    .filter((hit) => hit.rule.id.startsWith("cpp-"))
    .map((hit) => `${hit.line}:${hit.rule.id}`)
    .sort();
}

/** Rule ids reported for a one-line snippet (line numbers dropped). */
function idsOf(line: string, fileName?: string): string[] {
  return hitsOf(line, fileName).map((key) => key.split(":")[1] as string);
}

describe("C/C++ rule set", () => {
  it("loads the C/C++ rules with both languages and bilingual texts", () => {
    expect(cppRules.length).toBeGreaterThanOrEqual(40);
    for (const rule of cppRules) {
      expect(rule.languages.some((language) => language === "c" || language === "cpp")).toBe(true);
      expect(rule.title_zh).toBeTruthy();
      expect(rule.message_zh).toBeTruthy();
      expect(rule.remediation_zh).toBeTruthy();
      expect(rule.owasp).toBeTruthy();
      // Hotspots never claim more than low confidence.
      if (rule.kind === "hotspot") expect(rule.confidence).toBe("low");
    }
    // Rules that are not C++-only apply to .c files as well.
    const cppOnly = new Set(["cpp-cin-char-array", "cpp-auto-ptr"]);
    for (const rule of cppRules.filter((candidate) => !cppOnly.has(candidate.id))) {
      expect(rule.languages, rule.id).toEqual(["c", "cpp"]);
    }
  });

  it("reports exactly the EXPECTED.json seeds in the C/C++ fixtures", () => {
    const expected = loadExpected();
    const listed = new Set(
      expected.seeds
        .filter((seed) => seed.ruleId.startsWith("cpp-"))
        .map((seed) => `${seed.file}:${seed.line}:${seed.ruleId}:${seed.kind ?? "finding"}`),
    );
    const result = scanRules(inventory(VULNERABLE).files, ruleSet);
    const actual = new Set(
      result.hits
        .filter((hit) => hit.rule.id.startsWith("cpp-"))
        .map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}:${hit.rule.kind}`),
    );
    expect([...actual].filter((key) => !listed.has(key)).sort()).toEqual([]);
    expect([...listed].filter((key) => !actual.has(key)).sort()).toEqual([]);
    // Every C/C++ rule has a seed.
    const seeded = new Set([...listed].map((key) => key.split(":")[2]));
    expect(cppRules.map((rule) => rule.id).filter((id) => !seeded.has(id))).toEqual([]);
    // .c seeds are language c, everything else cpp.
    for (const seed of expected.seeds.filter((entry) => entry.ruleId.startsWith("cpp-"))) {
      expect(seed.language, seed.file).toBe(seed.file.endsWith(".c") ? "c" : "cpp");
    }
  });

  it("keeps the clean C/C++ fixtures free of C/C++ findings", () => {
    const result = scanRules(inventory(CLEAN).files, ruleSet);
    const hits = result.hits
      .filter((hit) => hit.rule.id.startsWith("cpp-"))
      .map((hit) => `${hit.file.relPath}:${hit.line}:${hit.rule.id}`);
    // The one known hotspot: `std::cin >> line` reads a std::string, which a
    // line-based rule cannot tell from a char array in the same file.
    // `system(cmd)` with a number formatted into cmd is a reading-list entry.
    expect(hits).toEqual([
      "cpp/hooks.c:19:cpp-system-api",
      "cpp/modern.cpp:16:cpp-cin-char-array",
    ]);
  });
});

describe("C/C++ rules: positives and their safe variants", () => {
  it("gets: always a finding, but not fgets, gets_s, methods or declarations", () => {
    expect(idsOf("    gets(buf);")).toEqual(["cpp-gets"]);
    expect(idsOf("    if (gets(line) == NULL) return;")).toEqual(["cpp-gets"]);
    expect(idsOf("    std::gets(buf);", "a.cpp")).toEqual(["cpp-gets"]);
    expect(idsOf("    fgets(buf, sizeof(buf), stdin);")).toEqual([]);
    expect(idsOf("    gets_s(buf, sizeof(buf));")).toEqual([]);
    expect(idsOf("    reader.gets(buf);", "a.cpp")).toEqual([]);
    expect(idsOf("    reader->gets(buf);", "a.cpp")).toEqual([]);
    expect(idsOf("extern char *gets(char *s);")).toEqual([]);
    expect(idsOf('    puts("do not use gets(buf) here");')).toEqual([]);
  });

  it("strcpy family: finding for argv/getenv, hotspot for runtime, nothing for literals", () => {
    expect(idsOf("    strcpy(buf, argv[1]);")).toEqual(["cpp-strcpy"]);
    expect(idsOf('    strcat(buf, getenv("HOME"));')).toEqual(["cpp-strcpy"]);
    expect(idsOf("    wcscpy(wbuf, name);")).toEqual(["cpp-strcpy-api"]);
    expect(idsOf("    lstrcatW(wbuf, name);")).toEqual(["cpp-strcpy-api"]);
    expect(idsOf('    strcpy(buf, "default");')).toEqual([]);
    expect(idsOf('    _tcscpy(buf, _T("default"));')).toEqual([]);
    expect(idsOf("    strcpy(buf, DEFAULT_NAME);")).toEqual([]);
    expect(idsOf("    my_strcpy(buf, name);")).toEqual([]);
    expect(idsOf("    strlcpy(buf, name, sizeof(buf));")).toEqual([]);
  });

  it("sprintf: unbounded %s is a hotspot, numeric or precision-limited formats are not", () => {
    expect(idsOf('    sprintf(out, "%s", argv[1]);')).toEqual(["cpp-sprintf"]);
    expect(idsOf('    sprintf(out, "name=%s", name);')).toEqual(["cpp-sprintf-api"]);
    expect(idsOf("    vsprintf(out, fmt, ap);")).toEqual(["cpp-sprintf-api"]);
    expect(idsOf('    sprintf(out, "%d:%lu", a, b);')).toEqual([]);
    expect(idsOf('    sprintf(out, "%.32s", name);')).toEqual([]);
    expect(idsOf('    sprintf(out, "100%%s", name);')).toEqual([]);
    expect(idsOf('    snprintf(out, sizeof(out), "%s", name);')).toEqual([]);
  });

  it("scanf: %s and %[ without a width only", () => {
    expect(idsOf('    scanf("%s", name);')).toEqual(["cpp-scanf-unbounded-string"]);
    expect(idsOf('    fscanf(fp, "%d %[^\\n]", &n, rest);')).toEqual(["cpp-scanf-unbounded-string"]);
    expect(idsOf('    sscanf(line, "%ls", wname);')).toEqual(["cpp-sscanf-unbounded-string"]);
    expect(idsOf('    scanf("%63s", name);')).toEqual([]);
    expect(idsOf('    scanf("%ms", &name);')).toEqual([]);
    expect(idsOf('    scanf("%*s %d", &n);')).toEqual([]);
    expect(idsOf('    scanf("%d", &n);')).toEqual([]);
    expect(idsOf('    scanf_s("%s", name, (unsigned)sizeof(name));')).toEqual([]);
  });

  it("format strings: a lone variable format is a finding; gettext and literals are not", () => {
    expect(idsOf("    printf(msg);")).toEqual(["cpp-format-string"]);
    expect(idsOf("    fprintf(stderr, argv[1]);")).toEqual(["cpp-format-string"]);
    expect(idsOf("    syslog(LOG_WARNING, entry->text);")).toEqual(["cpp-format-string"]);
    expect(idsOf("    snprintf(buf, sizeof(buf), msg);")).toEqual(["cpp-format-string"]);
    expect(idsOf("    printf(s.c_str());", "a.cpp")).toEqual(["cpp-format-string-cstr"]);
    expect(idsOf('    printf(_("Hello, world\\n"));')).toEqual([]);
    expect(idsOf('    printf(gettext("Hello\\n"));')).toEqual([]);
    expect(idsOf('    fprintf(stderr, _("error: %s\\n"), msg);')).toEqual([]);
    expect(idsOf('    printf("%s", msg);')).toEqual([]);
    expect(idsOf("    fprintf(stderr, USAGE);")).toEqual([]);
    expect(idsOf('    printf(verbose ? "yes\\n" : "no\\n");')).toEqual([]);
    expect(idsOf("    vfprintf(stderr, fmt, ap);")).toEqual([]);
    expect(idsOf("    snprintf(buf, sizeof(buf), fmt, a, b);")).toEqual(["cpp-format-string-variable"]);
    expect(idsOf("    logger.printf(msg);", "a.cpp")).toEqual([]);
    expect(idsOf("#define DBG(m) printf(m)")).toEqual([]);
    expect(idsOf("        printf(__VA_ARGS__);   \\")).toEqual([]);
    expect(idsOf("    printf(_s);")).toEqual([]);
  });

  it("err/warn formats only in files that include <err.h>", () => {
    expect(hitsOf("#include <err.h>\nvoid f(const char *m) { warnx(m); }")).toEqual([
      "2:cpp-format-string-err",
    ]);
    expect(hitsOf("void f(const char *m) { warnx(m); }")).toEqual([]);
    expect(hitsOf('#include <err.h>\nvoid f(const char *m) { warnx("%s", m); }')).toEqual([]);
  });

  it("commands: argv/getenv and concatenation are findings, literals are silent", () => {
    expect(idsOf("    system(argv[1]);")).toEqual(["cpp-system"]);
    expect(idsOf('    FILE *p = popen(getenv("CMD"), "r");')).toEqual(["cpp-system"]);
    expect(idsOf('    std::system(("rm -rf " + dir).c_str());', "a.cpp")).toEqual(["cpp-system-concat"]);
    expect(idsOf("    std::system(cmd.c_str());", "a.cpp")).toEqual(["cpp-system-api"]);
    expect(idsOf("    return system(cmd);")).toEqual(["cpp-system-api"]);
    expect(idsOf('    system("ls -l");')).toEqual([]);
    expect(idsOf("    if (system(NULL) == 0) return;")).toEqual([]);
    expect(idsOf('    FILE *p = popen("uname -a", "r");')).toEqual([]);
    expect(idsOf("    filesystem(path);")).toEqual([]);
    expect(idsOf("    os.system(cmd);", "a.cpp")).toEqual([]);
    expect(idsOf('    execl("/bin/sh", "sh", "-c", cmd, (char *)NULL);')).toEqual(["cpp-exec-shell-c"]);
    expect(idsOf('    execlp("sh", "sh", "-c", line, NULL);')).toEqual(["cpp-exec-shell-c"]);
    expect(idsOf('    execl("/bin/sh", "sh", "-c", "ls -l", (char *)NULL);')).toEqual([]);
    expect(idsOf('    execl("/usr/bin/env", "env", path, (char *)NULL);')).toEqual([]);
  });

  it("Windows process creation and DLL loading", () => {
    expect(idsOf("    CreateProcessW(NULL, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);", "w.cpp")).toEqual([
      "cpp-createprocess-unquoted",
    ]);
    expect(idsOf('    CreateProcessA(NULL, "\\"C:\\\\Program Files\\\\App\\\\app.exe\\" -v", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);', "w.cpp")).toEqual([]);
    expect(idsOf("    CreateProcessW(appPath, cmdline, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);", "w.cpp")).toEqual([]);
    expect(idsOf('    ShellExecuteW(NULL, L"open", L"https://www.example.com/", NULL, NULL, SW_SHOW);', "w.cpp")).toEqual([]);
    expect(idsOf('    LoadLibraryW(L"version.dll");', "w.cpp")).toEqual(["cpp-loadlibrary-relative"]);
    expect(idsOf('    LoadLibraryExW(L"version.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);', "w.cpp")).toEqual([]);
    expect(idsOf('    LoadLibraryA("C:\\\\Windows\\\\System32\\\\version.dll");', "w.cpp")).toEqual([]);
    expect(idsOf("    LoadLibraryW(fullPath);", "w.cpp")).toEqual([]);
    expect(idsOf("    if (MyIsBadReadPtr(p, 4)) return;", "w.cpp")).toEqual([]);
  });

  it("memory copies: size from the source, strncat and strncpy misuse", () => {
    expect(idsOf("    memcpy(dst, img.data, sizeof(img.data));")).toEqual(["cpp-copy-size-from-source"]);
    expect(idsOf("    memcpy(dst, src, strlen(src) + 1);")).toEqual(["cpp-copy-size-from-source"]);
    expect(idsOf("    memcpy(dst, src, sizeof(dst));")).toEqual([]);
    expect(idsOf("    memcpy(&a, &b, sizeof(b));")).toEqual([]);
    expect(idsOf("    memcpy(hdr.magic, MAGIC, sizeof(MAGIC));")).toEqual([]);
    expect(idsOf("    strncpy(dst, src, strlen(src));")).toEqual(["cpp-strncpy-source-length"]);
    expect(idsOf("    strncpy(dst, src, sizeof(dst) - 1);")).toEqual([]);
    expect(idsOf("    strncat(buf, s, sizeof(buf));")).toEqual(["cpp-strncat-full-size"]);
    expect(idsOf("    strncat(buf, s, sizeof buf - 1);")).toEqual(["cpp-strncat-full-size"]);
    expect(idsOf("    strncat(buf, s, sizeof(buf) - strlen(buf) - 1);")).toEqual([]);
    expect(idsOf('    strncat(buf, " != ", sizeof(buf) - offset);')).toEqual([]);
    expect(idsOf("    strncpy(name, src, sizeof(name));")).toEqual(["cpp-strncpy-no-nul"]);
    expect(idsOf("    strncpy(name, src, sizeof(name)); name[sizeof(name) - 1] = '\\0';")).toEqual([]);
    expect(idsOf('    strncpy(name, " - ", sizeof(name));')).toEqual([]);
  });

  it("allocation: dynamic alloca, unchecked multiplication, realloc self-assignment", () => {
    expect(idsOf("    char *p = alloca(len);")).toEqual(["cpp-alloca-dynamic"]);
    expect(idsOf("    char *p = alloca(256);")).toEqual([]);
    expect(idsOf("    char *p = alloca(sizeof(struct entry));")).toEqual([]);
    expect(idsOf("    char *p = alloca(BUF_SIZE);")).toEqual([]);
    expect(idsOf("    int *v = malloc(n * sizeof(int));")).toEqual(["cpp-malloc-multiply"]);
    expect(idsOf("    int *v = malloc(rows * cols);")).toEqual(["cpp-malloc-multiply"]);
    expect(idsOf("    v = realloc(old, count * size);")).toEqual(["cpp-malloc-multiply"]);
    expect(idsOf("    int *v = malloc(sizeof(int) * 16);")).toEqual([]);
    expect(idsOf("    int *v = calloc(n, sizeof(int));")).toEqual([]);
    expect(idsOf("    if (n > SIZE_MAX / sizeof(int)) return; v = malloc(n * sizeof(int));")).toEqual([]);
    expect(idsOf("    buf = realloc(buf, size);")).toEqual(["cpp-realloc-self-assign"]);
    expect(idsOf("    s->data = (char *)realloc(s->data, n);")).toEqual(["cpp-realloc-self-assign"]);
    expect(idsOf("    tmp = realloc(buf, size);")).toEqual([]);
    expect(idsOf("    a.p = realloc(b.p, size);")).toEqual([]);
    expect(idsOf("    newbuf = realloc(buf, size);")).toEqual([]);
  });

  it("temporary files, access(), privileges, chroot and umask", () => {
    expect(idsOf("    char *name = tmpnam(NULL);")).toEqual(["cpp-insecure-tempfile"]);
    expect(idsOf("    if (mktemp(tmpl) == NULL) return;")).toEqual(["cpp-insecure-tempfile"]);
    expect(idsOf("    int fd = mkstemp(tmpl);")).toEqual([]);
    expect(idsOf('    run("mktemp -d");')).toEqual([]);
    const toctou = "if (access(path, W_OK) == 0) {\n    fd = open(path, O_WRONLY);\n}";
    expect(hitsOf(toctou)).toEqual(["1:cpp-access-toctou"]);
    expect(hitsOf("if (access(path, R_OK) == 0) puts(path);")).toEqual([]);
    expect(hitsOf("if (!access(path, F_OK)) {\n    fd = open(path, O_RDONLY);\n}")).toEqual([]);
    expect(idsOf("    setuid(uid);")).toEqual(["cpp-setuid-unchecked"]);
    expect(idsOf("    if (setuid(uid) != 0) abort();")).toEqual([]);
    expect(idsOf("    rc = setresuid(uid, uid, uid);")).toEqual([]);
    expect(idsOf("int setuid(uid_t uid);")).toEqual([]);
    expect(hitsOf("    chroot(dir);")).toEqual(["1:cpp-chroot-without-chdir"]);
    expect(hitsOf('    if (chroot(dir) != 0 || chdir("/") != 0) abort();')).toEqual([]);
    expect(hitsOf('    chdir(dir);\n    chroot(".");')).toEqual([]);
    expect(idsOf("    umask(0);")).toEqual(["cpp-umask-zero"]);
    expect(idsOf("    umask(077);")).toEqual([]);
    expect(idsOf("    old = umask(0); umask(old);")).toEqual([]);
  });

  it("randomness: time seeds and rand() for security values", () => {
    expect(idsOf("    srand(time(NULL));")).toEqual(["cpp-srand-time"]);
    expect(idsOf("    srand((unsigned)time(0) ^ getpid());")).toEqual(["cpp-srand-time"]);
    expect(idsOf("    std::mt19937 gen(time(nullptr));", "a.cpp")).toEqual(["cpp-srand-time"]);
    expect(idsOf("    srand(42);")).toEqual([]);
    expect(idsOf("    session_key[i] = rand() % 256;")).toEqual(["cpp-rand-security-value"]);
    expect(idsOf("    nonce = random();")).toEqual(["cpp-rand-security-value"]);
    expect(idsOf("    authToken = rand();", "a.cpp")).toEqual(["cpp-rand-security-value"]);
    expect(idsOf("    int dice = rand() % 6 + 1;")).toEqual([]);
    expect(idsOf("    char *key = make_key(rand() % count);")).toEqual([]);
    expect(idsOf("    hashkey = rand();")).toEqual([]);
  });

  it("OpenSSL and libcurl", () => {
    expect(idsOf("    MD5_Init(&ctx);")).toEqual(["cpp-weak-hash"]);
    expect(idsOf("    md = EVP_md5();")).toEqual(["cpp-weak-hash"]);
    expect(idsOf("    git_SHA1_Init(&ctx);")).toEqual([]);
    expect(idsOf(" * the key is the prefix SHA1 (w/trailing NULs) of the")).toEqual([]);
    expect(idsOf("    md = EVP_sha256();")).toEqual([]);
    expect(idsOf("    EVP_DigestSignInit(mctx, NULL, EVP_sha1(), NULL, pkey);")).toEqual(["cpp-sha1-signature"]);
    expect(idsOf("    EVP_DigestInit_ex(mctx, EVP_sha1(), NULL);")).toEqual([]);
    expect(idsOf("    EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv);")).toEqual(["cpp-weak-cipher"]);
    expect(idsOf("    EVP_EncryptInit_ex(ctx, EVP_aes_256_ecb(), NULL, key, NULL);")).toEqual(["cpp-ecb-mode"]);
    expect(idsOf("    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, iv);")).toEqual([]);
    expect(idsOf("    ctx = SSL_CTX_new(SSLv3_client_method());")).toEqual(["cpp-ssl-legacy-protocol"]);
    expect(idsOf("    ctx = SSL_CTX_new(TLSv1_2_client_method());")).toEqual([]);
    expect(idsOf("    ctx = SSL_CTX_new(TLS_client_method());")).toEqual([]);
    expect(idsOf("    SSL_CTX_set_min_proto_version(ctx, TLS1_1_VERSION);")).toEqual(["cpp-ssl-legacy-protocol"]);
    expect(idsOf("    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);")).toEqual([]);
    expect(idsOf("    SSL_set_verify(ssl, SSL_VERIFY_NONE, NULL);")).toEqual(["cpp-ssl-verify-none"]);
    expect(idsOf("    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);")).toEqual([]);
    expect(idsOf("    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 0L);")).toEqual(["cpp-curl-tls-verify-disabled"]);
    expect(idsOf("    curl_easy_setopt(h, CURLOPT_PROXY_SSL_VERIFYPEER, FALSE);")).toEqual(["cpp-curl-tls-verify-disabled"]);
    expect(idsOf("    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);")).toEqual([]);
    expect(idsOf("    curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);")).toEqual([]);
    expect(idsOf(" *   curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);")).toEqual([]);
  });

  it("hard-coded credentials: char arrays and #define, not prompts or empty values", () => {
    expect(idsOf('static const char db_password[] = "s3cr3tPassw0rd";')).toEqual(["cpp-hardcoded-credential"]);
    expect(idsOf('char apiKey[33] = "ab12cd34ef56ab12";')).toEqual(["cpp-hardcoded-credential"]);
    expect(idsOf('#define ADMIN_PASSWORD "letMe1nNow"')).toEqual(["cpp-hardcoded-credential"]);
    expect(idsOf('static const char password_prompt[] = "Enter password:";')).toEqual([]);
    expect(idsOf('char password[] = "";')).toEqual([]);
    expect(idsOf("char password[64];")).toEqual([]);
    expect(idsOf('char password_fmt[] = "password=%s";')).toEqual([]);
    expect(idsOf('#define DEFAULT_PASSWORD "ftp@example.com"')).toEqual([]);
  });

  it("C++: cin into a buffer, auto_ptr", () => {
    expect(hitsOf("char name[32];\nstd::cin >> name;", "a.cpp")).toEqual(["2:cpp-cin-char-array"]);
    expect(hitsOf("char name[32];\nstd::cin >> std::setw(32) >> name;", "a.cpp")).toEqual([]);
    expect(hitsOf("std::string name;\nstd::cin >> name;", "a.cpp")).toEqual([]);
    expect(idsOf("    std::auto_ptr<Widget> w(new Widget);", "a.cpp")).toEqual(["cpp-auto-ptr"]);
    expect(idsOf("    std::unique_ptr<Widget> w(new Widget);", "a.cpp")).toEqual([]);
  });

  it("fopen: argv/getenv paths are low-confidence findings, literals are silent", () => {
    expect(idsOf('    FILE *f = fopen(argv[1], "r");')).toEqual(["cpp-path-traversal"]);
    expect(idsOf('    FILE *f = fopen(filename, "r");')).toEqual(["cpp-fopen-api"]);
    expect(idsOf('    FILE *f = fopen("/etc/app.conf", "r");')).toEqual([]);
  });

  it("review fixes: credential #define values that are names, not secrets", () => {
    expect(idsOf('#define ENV_PRIVATE_KEY "private_key"')).toEqual([]);
    expect(idsOf('#define PEM_STRUCTURE_PrivateKey "PrivateKeyInfo"')).toEqual([]);
    expect(idsOf('#define OSSL_PKEY_PARAM_PRIVATE_KEY_TYPE "type-specific"')).toEqual([]);
    expect(idsOf('#define BUS_ERROR_BAD_PASSWORD "org.freedesktop.home1.BadPassword"')).toEqual([]);
    expect(idsOf('#define SECRET_SCOPE "local.private"')).toEqual([]);
    expect(idsOf('#define ADMIN_PASSWORD "Hunter2-Prod"')).toEqual(["cpp-hardcoded-credential"]);
  });

  it("review fixes: an explicit (void) cast on setuid is a deliberate discard", () => {
    expect(idsOf("        (void) seteuid(olduid);")).toEqual([]);
    expect(idsOf("    (void)setgid(gid);")).toEqual([]);
    expect(idsOf("    if (x) setuid(uid);")).toEqual(["cpp-setuid-unchecked"]);
  });

  it("review fixes: comment lines and trailing // comments are not reported", () => {
    expect(idsOf(' *     while (scanf("%s %ld %s", action, &key, value)) {')).toEqual([]);
    expect(idsOf(" * then chroot(dir) is called before the privileges are dropped.")).toEqual([]);
    expect(idsOf(" *  RC4(&key, len, in, out);")).toEqual([]);
    expect(idsOf("// MD5_Init(&ctx);")).toEqual([]);
    expect(idsOf("/* gets(buf); */")).toEqual([]);
    expect(idsOf("    n = 1; // was: gets(buf);")).toEqual([]);
    expect(idsOf('    printf("see http://x"); gets(buf);')).toEqual(["cpp-gets"]);
    expect(idsOf("    *p = realloc(*p, n);")).toEqual(["cpp-realloc-self-assign"]);
  });

  it("review fixes: Microsoft _s printf family, casts and offsets as the format", () => {
    expect(idsOf("    printf_s(msg);", "w.cpp")).toEqual(["cpp-format-string"]);
    expect(idsOf("    fprintf_s(stderr, msg);", "w.cpp")).toEqual(["cpp-format-string"]);
    expect(idsOf("    sprintf_s(buf, sizeof(buf), msg);", "w.cpp")).toEqual(["cpp-format-string"]);
    expect(idsOf("    _snprintf_s(buf, sizeof(buf), _TRUNCATE, msg);", "w.cpp")).toEqual(["cpp-format-string"]);
    expect(idsOf("    StringCbPrintfW(buf, sizeof(buf), msg);", "w.cpp")).toEqual(["cpp-format-string"]);
    expect(idsOf('    sprintf_s(buf, sizeof(buf), "%s", msg);', "w.cpp")).toEqual([]);
    expect(idsOf("    printf((const char *)buf);")).toEqual(["cpp-format-string"]);
    expect(idsOf("    printf(&buf[1]);")).toEqual(["cpp-format-string"]);
    expect(idsOf("    printf(buf + 1);")).toEqual(["cpp-format-string"]);
    expect(idsOf("    syslog(LOG_ERR, fmt, user);")).toEqual(["cpp-format-string-variable"]);
    expect(idsOf("    sprintf(out, format, a);")).toEqual(["cpp-format-string-variable"]);
    expect(idsOf("#define LOG(fmt, ...) fprintf(stderr, fmt, __VA_ARGS__)")).toEqual([]);
  });

  it("review fixes: std::getenv and SSL_CTX_set_verify(ctx, 0, ...)", () => {
    expect(idsOf('    std::system(std::getenv("PAGER"));', "a.cpp")).toEqual(["cpp-system"]);
    expect(idsOf("    SSL_CTX_set_verify(ctx, 0, NULL);")).toEqual(["cpp-ssl-verify-none"]);
  });

  it("review calibration: test trees, sscanf, path traversal and umask", () => {
    const line = "    curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 0L);";
    expect(idsOf(line, "tests/libtest/lib1.c")).toEqual([]);
    expect(idsOf(line, "test/client.c")).toEqual([]);
    expect(idsOf(line, "docs/examples/https.c")).toEqual(["cpp-curl-tls-verify-disabled"]);
    const byId = new Map(cppRules.map((rule) => [rule.id, rule]));
    expect(byId.get("cpp-sscanf-unbounded-string")?.confidence).toBe("low");
    expect(byId.get("cpp-scanf-unbounded-string")?.confidence).toBe("medium");
    expect(byId.get("cpp-path-traversal")?.severity).toBe("medium");
    expect(byId.get("cpp-umask-zero")?.kind).toBe("hotspot");
    expect(byId.get("cpp-umask-zero")?.confidence).toBe("low");
  });

  it("keeps the credential value out of every output file", async () => {
    const root = path.join(temp, "redact");
    writeFile(root, "src/config.c", 'static const char admin_password[] = "Zq7RedactMe99";\n');
    const out = path.join(temp, "redact-out");
    const result = await scanProject({ root, out, offline: true, formats: ["md", "json", "sarif"] });
    expect(result.findings.some((finding) => finding.ruleId === "cpp-hardcoded-credential")).toBe(true);
    expect(readAllOutputFiles(out)).not.toContain("Zq7RedactMe99");
  });

  // The engine matches C/C++ line by line. Until the planned C lexer exists,
  // lines that start like a comment and calls after a // marker are skipped;
  // the body of a block comment whose lines do not start with * is not.
  it.todo("does not report a call on a block-comment line without a leading * (needs the C lexer)");
  it.todo("reports printf(\\n    msg); split over two lines (needs the C lexer)");
  it.todo("reports strcpy(dst,\\n    argv[1]); split over two lines (needs the C lexer)");
});
