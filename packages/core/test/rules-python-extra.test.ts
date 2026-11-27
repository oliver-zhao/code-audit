import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { inventory } from "../src/inventory.js";
import { loadRules, scanRules } from "../src/rules.js";
import { RULES_DIR, cleanup, makeTempDir, writeFile } from "./helpers.js";

// Positive and negative cases for the rules in rules/sast/python-extra.yml and
// for the patterns of python.yml / python-web.yml that this stage widened.

const temp = makeTempDir("rules-python-extra");
const ruleSet = loadRules(RULES_DIR);
let counter = 0;

afterAll(() => cleanup(temp));

/** Scan one file and return "line:ruleId" for the rules of interest. */
function scan(lines: string[], ruleIds: string[], relPath = "app.py"): string[] {
  counter += 1;
  const root = path.join(temp, `case-${counter}`);
  writeFile(root, relPath, `${lines.join("\n")}\n`);
  const result = scanRules(inventory(root).files, ruleSet);
  return result.hits
    .filter((hit) => ruleIds.includes(hit.rule.id))
    .map((hit) => `${hit.line}:${hit.rule.id}`);
}

const FLASK = "from flask import Flask, request";

interface Case {
  rule: string;
  header?: string[];
  bad: string[];
  good: string[];
}

// Every line in `bad` must be reported by the rule; no line in `good` may be.
const CASES: Case[] = [
  {
    rule: "py-xss-response-request",
    header: ["from django.http import HttpResponse", FLASK],
    bad: [
      'HttpResponse("Hello " + request.GET["name"])',
      'make_response(f"<p>{request.args[\'who\']}</p>")',
      'HTMLResponse(content="<b>" + request.query_params["q"])',
      'Response("<h1>" + request.args["n"] + "</h1>")',
    ],
    good: [
      'HttpResponse("Hello " + escape(request.GET["name"]))',
      'HttpResponse(request.GET["name"], content_type="text/plain")',
      // Review item 7: positional content type.
      'HttpResponse("Hi " + request.GET["name"], "text/plain")',
      // A bare Response(request.data) is the Django REST framework JSON echo.
      "Response(request.data)",
      'HttpResponse(json.dumps(request.GET.dict()))',
      'HttpResponseRedirect("/" + request.GET["next"])',
      'make_response(redirect(request.args["next"]))',
      'make_response(render_template("page.html", q=request.args["q"]))',
      'note = "HttpResponse(request.GET[\'x\'])"',
    ],
  },
  {
    rule: "py-xss-return-html",
    header: [FLASK],
    bad: [
      'return "<h1>Hello " + request.args.get("name", "") + "</h1>"',
      'return f"<div class=x>{request.form[\'msg\']}</div>"',
    ],
    good: [
      'return "<h1>Hello " + markupsafe.escape(request.args["name"]) + "</h1>"',
      'return "Hello " + request.args["name"]',
      'return f"<p>{name}</p>"',
    ],
  },
  {
    // Review item 2: FastAPI encodes a returned str as JSON.
    rule: "py-xss-return-html",
    header: ["from fastapi import FastAPI, Request"],
    bad: [],
    good: ['return "<h1>Hello " + request.query_params["name"] + "</h1>"'],
  },
  {
    rule: "py-html-response-dynamic",
    bad: ['return HTMLResponse(f"<h2>{title}</h2>")'],
    good: [
      'return HTMLResponse("<h2>static</h2>")',
      'return HTMLResponse(f"<h2>{escape(title)}</h2>")',
      'return HttpResponse(f"count={n}")',
    ],
  },
  {
    rule: "py-format-html-prebuilt",
    bad: [
      'format_html(f"<a href=\'{url}\'>{label}</a>")',
      'format_html("<b>%s</b>" % name)',
      'format_html("<b>{}</b>".format(name))',
    ],
    good: [
      'format_html("<a href=\'{}\'>{}</a>", url, label)',
      // Review item 4: two literals joined with + are constant.
      'format_html("<b>{}</b>" + "<i>{}</i>", a, b)',
    ],
  },
  {
    rule: "py-ssrf-host-request",
    header: [FLASK],
    bad: [
      'requests.get(f"http://{request.args[\'host\']}/status", timeout=5)',
      'requests.post(url=f"{request.form[\'target\']}/hook", timeout=5)',
      'urllib.request.urlopen("http://" + request.args["host"])',
      'requests.get("http://%s/status" % request.args["host"], timeout=5)',
      'requests.get("http://{}/status".format(request.args["host"]), timeout=5)',
      'httpx.Client().get(f"https://{request.args[\'host\']}/x")',
      'requests.Session().get(f"https://{request.args[\'host\']}/x", timeout=5)',
    ],
    good: [
      'requests.get(f"https://api.example.com/items/{request.args[\'id\']}", timeout=5)',
      'requests.get("https://api.example.com/" + request.args["path"], timeout=5)',
    ],
  },
  {
    rule: "py-ssrf-api",
    header: [FLASK],
    bad: ["requests.get(callback_url, timeout=5)", "httpx.post(self.webhook, json=body)"],
    good: [
      'requests.get("https://example.com", timeout=5)',
      "requests.get(build(), timeout=5)",
      'text = "requests.get(url) is documented here"',
    ],
  },
  {
    rule: "py-nosql-where",
    bad: [
      'db.users.find({"$where": "this.name == \'" + name + "\'"})',
      'db.users.find({"$where": f"this.age > {age}"})',
    ],
    good: ['db.users.find({"$where": "this.age > 18"})', 'db.users.find({"age": {"$gt": age}})'],
  },
  {
    rule: "py-nosql-request-filter",
    header: ["from pymongo import MongoClient", FLASK],
    bad: [
      "db.users.find_one(request.get_json())",
      'db.users.find_one({"name": request.json["name"], "pw": request.json["pw"]})',
      "db.orders.delete_many(request.json)",
    ],
    good: [
      'db.users.find_one({"name": str(body["name"])})',
      'db.users.find_one({"name": request.form["name"]})',
      'request.args.get("q", "").find("x")',
      // Review item 8: str.find on a local name.
      'name.find(request.args.get("q", ""))',
    ],
  },
  {
    rule: "py-ldap-filter-built",
    header: ["import ldap"],
    bad: [
      'search_filter = "(&(uid=" + username + ")(objectClass=person))"',
      'query = f"(mail={email})"',
      'flt = "(cn=%s)" % name',
    ],
    good: [
      'search_filter = "(&(uid=" + escape_filter_chars(username) + "))"',
      'base_filter = "(objectClass=person)"',
    ],
  },
  {
    rule: "py-regex-request",
    header: [FLASK],
    bad: ['re.compile(request.args["q"])', 're.search(request.form["pattern"], text)'],
    good: ['re.compile(re.escape(request.args["q"]))', 're.search("^[a-z]+$", request.args["q"])'],
  },
  {
    rule: "py-mass-assignment",
    header: [FLASK],
    bad: [
      "User(**request.json)",
      "Order.objects.create(owner=user, **request.POST.dict())",
      "Product.objects.filter(**request.GET.dict())",
    ],
    good: [
      'User(name=request.json["name"])',
      "User(**cleaned)",
      'urlencode({**request.GET, "page": 2})',
      "handler(**request.match_info)",
    ],
  },
  {
    rule: "py-cors-credentials-default-origin",
    bad: ["CORS(app, supports_credentials=True)"],
    good: [
      'CORS(app, origins=["https://app.example.com"], supports_credentials=True)',
      'CORS(app, resources={r"/api/*": {"origins": "https://a.example"}}, supports_credentials=True)',
      "CORS(app)",
    ],
  },
  {
    // Review item 5: origins configured through init_app in the same file.
    rule: "py-cors-credentials-default-origin",
    header: ['cors.init_app(app, origins=["https://app.example.com"])'],
    bad: [],
    good: ["cors = CORS(supports_credentials=True)"],
  },
  {
    rule: "py-cors-regex-any",
    bad: [
      'app.add_middleware(CORSMiddleware, allow_origin_regex=".*", allow_credentials=True)',
      'CORS(app, origins=r"^.*$", supports_credentials=True)',
      'CORS(app, origins=r"https?://.*", supports_credentials=True)',
    ],
    good: [
      'app.add_middleware(CORSMiddleware, allow_origin_regex=r"https://.*\\.example\\.com", allow_credentials=True)',
      'app.add_middleware(CORSMiddleware, allow_origin_regex=".*")',
    ],
  },
  {
    rule: "py-django-weak-password-hasher",
    bad: ['PASSWORD_HASHERS = ["django.contrib.auth.hashers.UnsaltedMD5PasswordHasher"]'],
    good: [
      'PASSWORD_HASHERS = ["django.contrib.auth.hashers.PBKDF2PasswordHasher", "django.contrib.auth.hashers.MD5PasswordHasher"]',
      // Review item 3: test-only settings.
      'if TESTING: PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]',
      "if TESTING:",
      '    PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]',
      'settings.PASSWORD_HASHERS = ["django.contrib.auth.hashers.MD5PasswordHasher"]',
    ],
  },
  {
    rule: "py-django-xframe-exempt",
    bad: ["@xframe_options_exempt", "view = xframe_options_exempt(view)"],
    good: ["@xframe_options_sameorigin"],
  },
  {
    rule: "py-jwt-hardcoded-key",
    bad: [
      'jwt.encode(payload, "s3cr3t-signing-key", algorithm="HS256")',
      'jwt.encode({"user": name, "role": "admin"}, "another-literal-key")',
      'jwt.decode(token, key="literal-key-1234", algorithms=["HS256"])',
    ],
    good: [
      'jwt.encode(payload, settings.JWT_KEY, algorithm="HS256")',
      'jwt.encode({"user": "bob", "role": "admin"}, key)',
      'jwt.decode(token, "-----BEGIN PUBLIC KEY-----abc", algorithms=["RS256"])',
    ],
  },
  {
    rule: "py-ssl-insecure-version",
    bad: [
      "ssl.SSLContext(ssl.PROTOCOL_TLSv1)",
      "context.minimum_version = ssl.TLSVersion.TLSv1",
      "SSL.Context(SSL.TLSv1_METHOD)",
    ],
    good: [
      "context.minimum_version = ssl.TLSVersion.TLSv1_2",
      "context.options |= ssl.OP_NO_TLSv1",
      "if context.protocol == ssl.PROTOCOL_TLSv1: pass",
      'if hasattr(ssl, "PROTOCOL_TLSv1"): pass',
    ],
  },
  {
    rule: "py-weak-key-size",
    bad: [
      "rsa.generate_private_key(public_exponent=65537, key_size=1024)",
      "rsa.generate_private_key(65537, 512)",
      "RSA.generate(1024)",
      "ec.generate_private_key(ec.SECP192R1())",
      "paramiko.RSAKey.generate(1024)",
      "key.generate_key(crypto.TYPE_RSA, 1024)",
    ],
    good: [
      "rsa.generate_private_key(public_exponent=65537, key_size=2048)",
      "RSA.generate(3072)",
      "ec.generate_private_key(ec.SECP256R1())",
    ],
  },
  {
    rule: "py-pbkdf2-low-iterations",
    bad: [
      "PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=1000)",
      'hashlib.pbkdf2_hmac("sha256", password, salt, 5000)',
    ],
    good: [
      "PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)",
      'hashlib.pbkdf2_hmac("sha256", password, salt, 600000)',
      'hashlib.pbkdf2_hmac("sha256", password, salt, ITERATIONS)',
    ],
  },
  {
    rule: "py-timing-unsafe-compare",
    bad: [
      "if expected == received_signature: pass",
      "if hmac.new(k, b, sha256).hexdigest() != sig: pass",
      "if provided_api_key == settings.API_KEY: pass",
    ],
    good: [
      "if hmac.compare_digest(expected, received_signature): pass",
      'if received_signature == "": pass',
      "if signature is None: pass",
      "if token_type == expected_type: pass",
      "return self.signature == other.signature",
      "if sha256(data).hexdigest() != expected_sha256: pass",
      "if len(signature) == 64: pass",
      "if alg == signature.algorithm: pass",
      "if digestmod == HMAC_SHA256_MAC: pass",
      "if hashlib.sha256(blob).hexdigest() == expected: pass",
    ],
  },
  {
    rule: "py-cleartext-protocol",
    header: ["import telnetlib", "from ftplib import FTP, FTP_TLS"],
    bad: ["telnetlib.Telnet(host)", "FTP(host)"],
    good: ["FTP_TLS(host)"],
  },
  {
    rule: "py-paramiko-exec-dynamic",
    header: ["import paramiko"],
    bad: [
      'client.exec_command(f"rm -rf {directory}")',
      'client.exec_command("cat " + name)',
      'client.exec_command(command="cat " + name)',
    ],
    good: ['client.exec_command("uptime")', 'client.exec_command("cat " + shlex.quote(name))'],
  },
  {
    rule: "py-xmlrpc-dotted-names",
    bad: [
      "server.register_instance(api, allow_dotted_names=True)",
      "server.register_instance(api, True)",
    ],
    good: ["server.register_instance(api)", "server.register_instance(api, False)"],
  },
  {
    rule: "py-mako-autoescape-missing",
    header: ["from mako.lookup import TemplateLookup"],
    bad: ['TemplateLookup(directories=["templates"])'],
    good: ['TemplateLookup(directories=["templates"], default_filters=["h"])'],
  },
  {
    rule: "py-unpack-archive",
    bad: ["shutil.unpack_archive(upload, target)"],
    good: ['shutil.unpack_archive(upload, target, filter="data")'],
  },
  {
    rule: "py-lxml-parse-default",
    header: ["from lxml import etree"],
    bad: ["etree.parse(path)", "etree.fromstring(data)"],
    good: [
      "etree.parse(path, parser=HARDENED)",
      "etree.fromstring(data, HARDENED)",
      "defusedxml.lxml.parse(path)",
    ],
  },
  {
    rule: "py-hf-trust-remote-code",
    bad: [
      "AutoModel.from_pretrained(name, trust_remote_code=True)",
      'pipeline("text-generation", model=model_id, trust_remote_code=True)',
    ],
    good: [
      "AutoModel.from_pretrained(name, trust_remote_code=False)",
      'AutoModel.from_pretrained(name, revision="0123456789abcdef0123456789abcdef01234567", trust_remote_code=True)',
      'raise ValueError("Please set the option `trust_remote_code=True` to load this model.")',
      "trust_remote_code = True",
    ],
  },
  {
    rule: "py-langchain-dangerous-option",
    bad: [
      "PALChain.from_math_prompt(llm, allow_dangerous_code=True)",
      'FAISS.load_local("index", embeddings, allow_dangerous_deserialization=True)',
      "RequestsToolkit(requests_wrapper=w, allow_dangerous_requests=True)",
    ],
    good: [
      "PALChain.from_math_prompt(llm)",
      'note = "allow_dangerous_code=True is never set"',
      // Review item 6: an upper-case setting name is not the LangChain option.
      "ALLOW_DANGEROUS_REQUESTS = True",
    ],
  },
  {
    rule: "py-llm-code-tool",
    bad: ["tools = [PythonREPLTool()]", 'load_tools(["terminal", "llm-math"], llm=llm)'],
    good: ['load_tools(["llm-math"], llm=llm)'],
  },
  {
    rule: "py-llm-output-exec",
    bad: ["exec(completion.choices[0].message.content)", "eval(llm_output)"],
    good: [
      "exec(compile(source, path, 'exec'))",
      "action = ACTIONS.get(completion.choices[0].message.content)",
    ],
  },
  {
    rule: "py-llm-output-shell",
    bad: ["os.system(llm_output)", "subprocess.run(generated_command)"],
    // With shell=True py-subprocess-shell reports it as a finding instead.
    good: ["subprocess.run(generated_command, shell=True)", "os.system(cmd)"],
  },
  {
    rule: "py-hf-trust-remote-code-default",
    bad: [
      "def load(name, trust_remote_code: bool = True): return name",
      "async def load2(name, trust_remote_code=True): return name",
    ],
    good: [
      "def load(name, trust_remote_code: bool = False): return name",
      "def load3(name, trust_remote_code=None): return name",
    ],
  },
  // Widened patterns of existing rules.
  {
    // A numeric-only LDAP filter (clean taint fixture) is not injectable.
    rule: "py-ldap-injection",
    header: ["import ldap"],
    bad: ['conn.search_s(base, 2, "(uid=%s)" % uid)'],
    good: ['conn.search_s(base, 2, "(uidNumber=%d)" % number)'],
  },
  {
    rule: "py-session-cookie-insecure",
    bad: [
      'app.config["SESSION_COOKIE_HTTPONLY"] = False',
      "app.config.update(SESSION_COOKIE_SECURE=False)",
    ],
    good: ['app.config["SESSION_COOKIE_HTTPONLY"] = True', '{"SESSION_COOKIE_SECURE": False}'],
  },
  {
    rule: "py-insecure-deserialization",
    header: [FLASK],
    bad: [
      'joblib.load(request.files["model"])',
      'pd.read_pickle(request.files["frame"])',
      'torch.load(request.files["ckpt"])',
    ],
    good: ['torch.load(request.files["ckpt"], weights_only=True)'],
  },
  {
    rule: "py-chmod-777",
    bad: ["os.chmod(path, stat.S_IRWXU | stat.S_IRWXO)", "os.chmod(path, 0o777)"],
    good: ["os.chmod(path, mode & ~stat.S_IWOTH)", "os.chmod(path, 0o640)"],
  },
  {
    // Review: "~" in a path must not hide a world-writable mode.
    rule: "py-chmod-777",
    bad: ['os.chmod(os.path.expanduser("~/shared"), 0o777)'],
    good: [],
  },
];

describe("python-extra rules: positive and negative cases", () => {
  for (const testCase of CASES) {
    it(`${testCase.rule} reports the dangerous forms and not the safe ones`, () => {
      const header = testCase.header ?? [];
      const bad = scan([...header, ...testCase.bad], [testCase.rule]);
      const badLines = testCase.bad.map(
        (_, index) => `${header.length + index + 1}:${testCase.rule}`,
      );
      expect(bad).toEqual(badLines);
      const good = scan([...header, ...testCase.good], [testCase.rule]);
      expect(good).toEqual([]);
    });
  }

  it("every rule of python-extra.yml has a case here", () => {
    const covered = new Set(CASES.map((testCase) => testCase.rule));
    const extra = ruleSet.rules.filter((rule) => rule.id.startsWith("py-")).map((rule) => rule.id);
    const own = [
      "py-xss-response-request", "py-xss-return-html", "py-html-response-dynamic",
      "py-format-html-prebuilt", "py-ssrf-host-request", "py-ssrf-api", "py-nosql-where",
      "py-nosql-request-filter", "py-ldap-filter-built", "py-regex-request",
      "py-mass-assignment", "py-cors-credentials-default-origin", "py-cors-regex-any",
      "py-django-weak-password-hasher", "py-django-xframe-exempt", "py-jwt-hardcoded-key",
      "py-ssl-insecure-version", "py-weak-key-size", "py-pbkdf2-low-iterations",
      "py-timing-unsafe-compare", "py-cleartext-protocol", "py-paramiko-exec-dynamic",
      "py-xmlrpc-dotted-names", "py-mako-autoescape-missing", "py-unpack-archive",
      "py-lxml-parse-default", "py-hf-trust-remote-code", "py-langchain-dangerous-option",
      "py-llm-code-tool", "py-llm-output-exec", "py-llm-output-shell",
      "py-hf-trust-remote-code-default",
    ];
    for (const id of own) {
      expect(extra).toContain(id);
      expect(covered.has(id), id).toBe(true);
    }
  });
});

describe("python-extra rules: regex cost", () => {
  // Review item 1: an unbounded string-literal body inside a repeated gap made
  // py-hf-trust-remote-code quadratic on input such as a("\' repeated.
  it("runs py-hf-trust-remote-code and the call-located rules in linear time on hostile input", () => {
    const ids = ["py-hf-trust-remote-code", "py-mass-assignment", "py-hf-trust-remote-code-default"];
    for (const id of ids) {
      const rule = ruleSet.rules.find((candidate) => candidate.id === id);
      const locator = rule?.compiled.locator;
      expect(locator, id).toBeDefined();
      if (!locator) continue;
      for (const unit of ['a("\\\'', "a(", 'a("x" ', "f(**", "def f("]) {
        const time = (length: number): number => {
          const text = unit.repeat(Math.ceil(length / unit.length));
          const regex = new RegExp(locator.source, locator.flags);
          const start = performance.now();
          for (const match of text.matchAll(regex)) void match;
          return performance.now() - start;
        };
        time(1_000);
        const large = time(100_000);
        expect(large, `${id} on ${JSON.stringify(unit)}`).toBeLessThan(400);
      }
    }
  });
});

describe("python-extra rules: context", () => {
  it("does not report the noisy hotspots and sample-only findings in test or example trees", () => {
    const lines = [
      "if expected == received_signature: pass",
      "shutil.unpack_archive(upload, target)",
      "AutoModel.from_pretrained(name, trust_remote_code=True)",
      'jwt.encode(payload, "s3cr3t-signing-key", algorithm="HS256")',
    ];
    const ids = ["py-timing-unsafe-compare", "py-unpack-archive", "py-hf-trust-remote-code", "py-jwt-hardcoded-key"];
    expect(scan(lines, ids, "tests/test_auth.py")).toEqual([]);
    expect(scan(lines, ["py-hf-trust-remote-code", "py-jwt-hardcoded-key"], "examples/demo.py")).toEqual([]);
    expect(scan(lines, ["py-hf-trust-remote-code"], "src/models/convert_weights_to_hf.py")).toEqual([]);
    expect(scan(lines, ids, "src/app.py")).toHaveLength(4);
  });

  it("gates framework rules on the imports of the file", () => {
    // Without a pymongo / ldap / paramiko / mako / lxml / web-framework import
    // the generic method names are not reported.
    const lines = [
      "db.users.find_one(request.get_json())",
      'search_filter = "(&(uid=" + username + "))"',
      'client.exec_command("cat " + name)',
      'TemplateLookup(directories=["templates"])',
      "etree.parse(path)",
      "requests.get(callback_url, timeout=5)",
      'return "<b>" + request.args["x"] + "</b>"',
    ];
    const ids = [
      "py-nosql-request-filter", "py-ldap-filter-built", "py-paramiko-exec-dynamic",
      "py-mako-autoescape-missing", "py-lxml-parse-default", "py-ssrf-api", "py-xss-return-html",
    ];
    expect(scan(lines, ids, "lib/helpers.py")).toEqual([]);
  });

  it("matches a call that spans several lines and reports its first line", () => {
    const hits = scan(
      [
        "from transformers import AutoModel",
        "model = AutoModel.from_pretrained(",
        "    name,",
        "    trust_remote_code=True,",
        ")",
        "PASSWORD_HASHERS = [",
        '    "django.contrib.auth.hashers.SHA1PasswordHasher",',
        "]",
      ],
      ["py-hf-trust-remote-code", "py-django-weak-password-hasher"],
      "settings.py",
    );
    expect(hits).toEqual(["2:py-hf-trust-remote-code", "6:py-django-weak-password-hasher"]);
  });

  it("does not report a rule inside a comment or a docstring", () => {
    const hits = scan(
      [
        '"""Never call exec(completion.choices[0].message.content) or',
        "AutoModel.from_pretrained(name, trust_remote_code=True).",
        '"""',
        "# requests.get(f\"http://{request.args['host']}/\")",
        "x = 1  # ssl.SSLContext(ssl.PROTOCOL_TLSv1)",
      ],
      ["py-llm-output-exec", "py-hf-trust-remote-code", "py-ssrf-host-request", "py-ssl-insecure-version"],
    );
    expect(hits).toEqual([]);
  });

  it("never shows the literal JWT key in the evidence", () => {
    counter += 1;
    const root = path.join(temp, `case-${counter}`);
    writeFile(root, "auth.py", 'token = jwt.encode(payload, "s3cr3t-signing-key-0042", algorithm="HS256")\n');
    const hits = scanRules(inventory(root).files, ruleSet).hits.filter(
      (hit) => hit.rule.id === "py-jwt-hardcoded-key",
    );
    expect(hits).toHaveLength(1);
    expect(hits[0]?.evidence).not.toContain("s3cr3t-signing-key-0042");
    expect(hits[0]?.evidence).toContain("jwt.encode(payload");
  });

  it.todo(
    "py-jwt-hardcoded-key: a key given as a module constant assigned a literal elsewhere in the file " +
      "(SECRET = 'x'; jwt.encode(p, SECRET)) needs data flow; only the literal at the call is matched",
  );
  it.todo(
    "py-xss-response-request / py-taint-xss: an HTML string returned from a Flask view through a variable " +
      "(body = '<b>' + name; return body) is not matched by the line rule; the taint rule does not treat " +
      "`return` as a sink",
  );
});
