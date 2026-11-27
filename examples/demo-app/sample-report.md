<!-- Sample output: `code-audit scan examples/demo-app --offline --no-external --out /tmp/code-audit-demo`, built-in engines only, no OSV.dev lookups, code-audit 0.3.0. Absolute paths shortened. Without `--offline` the scan also checks the pinned dependencies in requirements.txt against OSV.dev. -->

# Source Code Security Audit Report

> **Candidate results, not reviewed (unverified)**
>
> Deterministic scan produced candidates; review before acting.

## 1. Executive Summary

**13 findings count toward the exit code** (severity ≥ high, confidence ≥ medium); a scan with these thresholds exits 1.

**Findings at confidence ≥ medium**

| Category | Critical | High | Medium | Low | Info | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Code | 4 | 4 | 1 | 0 | 0 | 9 |
| Secrets | 0 | 2 | 0 | 0 | 0 | 2 |
| Configuration / IaC | 0 | 3 | 0 | 1 | 0 | 4 |
| Dependencies (advisories) | 0 | 0 | 0 | 0 | 0 | 0 |
| **Total** | **4** | **9** | **1** | **1** | **0** | **15** |

- Low-confidence candidates (confidence below medium, not counted above): 0
- Review hotspots (uses of dangerous APIs, not counted above): 2

> Counted: active findings (not suppressed, not marked false positive) at confidence ≥ medium. Low-confidence candidates and review hotspots are listed separately and are not part of these numbers.

### Top risks

1. **CRITICAL** · high · Code — Python SQL statement built with string formatting — app/server.py:21
2. **CRITICAL** · high · Code — Python unpickles request data — app/server.py:46
3. **CRITICAL** · high · Code — Request data in a child\_process shell command — web/tools.js:8
4. **CRITICAL** · high · Code — Request data evaluated as JavaScript — web/tools.js:12
5. **HIGH** · high · Secrets — Hardcoded AWS access key — config/prod.env:4
6. **HIGH** · high · Configuration / IaC — GitHub Actions script injection — .github/workflows/triage.yml:13
7. **HIGH** · high · Configuration / IaC — Dockerfile executes a remote script with curl \| sh — Dockerfile:4
8. **HIGH** · medium · Secrets — Possible hardcoded password or API key assignment — config/prod.env:3
9. **HIGH** · medium · Code — Hard-coded SECRET\_KEY — app/server.py:10
10. **HIGH** · medium · Code — Python subprocess with shell=True and a command computed at runtime — app/server.py:41

3 more critical/high findings are listed in the sections below.

### Remediation priorities

| Priority | Code, secrets and configuration findings | Vulnerable packages |
| --- | ---: | ---: |
| Immediate (Critical/High) | 13 | 0 |
| This week (Medium) | 1 | 0 |
| This month (Low/Info) | 1 | 0 |

> Confidence reflects how much input control is visible on the matched line; low-confidence API-only hits need manual review.

### Run details

- Target: `examples/demo-app`
- Run ID: `20261127T143732Z-479f2b6d` · Date: 2026-11-27 14:37:32Z
- Range: examples/demo-app
- Tool version: code-audit 0.3.0, Node.js v24.22.1 · Profile: standard · Offline: yes
- Model: No LLM invoked (deterministic engines)

## 2. Findings: code, secrets and configuration

### Python SQL statement built with string formatting — `py-sql-injection`

**CRITICAL** · Code · CWE-89 · A03:2021 · 1 location

**Description**: A value is formatted into the SQL text \(f-string, concatenation, % or .format\(\) in value position\), or the statement comes straight from the request.

**Remediation**: Keep the SQL text constant and pass values as bound parameters \(? / %s placeholders with a parameter tuple\).

**AUD-2026-0001** · app/server.py:21 · Confidence: high · Status: candidate · Engine: builtin-rules

~~~text
cursor.execute(f"SELECT id, name FROM users WHERE name = '{name}'")
~~~

### Python unpickles request data — `py-insecure-deserialization`

**CRITICAL** · Code · CWE-502 · A08:2021 · 1 location

**Description**: pickle, dill, marshal, jsonpickle, joblib, shelve, pandas.read\_pickle or torch.load deserializes a value read from the request, which lets the sender execute arbitrary code.

**Remediation**: Use JSON or another data-only format for anything that crosses a trust boundary.

**AUD-2026-0002** · app/server.py:46 · Confidence: high · Status: candidate · Engine: builtin-rules

~~~text
return {"session": str(pickle.loads(request.data))}
~~~

### Request data in a child\_process shell command — `js-command-injection-request`

**CRITICAL** · Code · CWE-78 · A03:2021 · 1 location

**Description**: A request value is part of a shell command: remote command execution.

**Remediation**: Never pass request data to a shell; use execFile/spawn with a fixed program and an argument array, and allowlist values.

**AUD-2026-0003** · web/tools.js:8 · Confidence: high · Status: candidate · Engine: builtin-rules

~~~text
exec("ping -c 1 " + req.query.host, (error, stdout) =&gt; res.send(stdout));
~~~

### Request data evaluated as JavaScript — `js-code-injection-request`

**CRITICAL** · Code · CWE-95 · A03:2021 · 1 location

**Description**: A request value reaches eval, Function, vm, a string timer or a math evaluator: server-side JavaScript injection \(remote code execution\).

**Remediation**: Parse the value \(Number\(\), JSON.parse\) instead of evaluating it; never run request data as code.

**AUD-2026-0004** · web/tools.js:12 · Confidence: high · Status: candidate · Engine: builtin-rules

~~~text
res.send(String(eval(req.query.expr)));
~~~

### Hardcoded AWS access key — `secret-aws-access-key`

**HIGH** · Secrets · CWE-798 · A07:2021 · 1 location

**Description**: Possible plaintext credential detected; evidence is redacted in every report.

**Remediation**: Rotate the key in AWS IAM immediately, switch to environment variables or an instance role, and purge the key from Git history.

**AUD-2026-0006** · config/prod.env:4 · Confidence: high · Status: candidate · Engine: builtin-secrets

~~~text
AWS_ACCESS_KEY_ID=AKIA**************TS
~~~

### GitHub Actions script injection — `gha-script-injection`

**HIGH** · Configuration / IaC · CWE-94 · A03:2021 · 1 location

**Description**: An event field that an outside contributor controls \(title, body, branch name, commit message\) is expanded into a run script before the shell parses it, allowing command injection.

**Remediation**: Pass the value through env \(env FOO set to the expression\) and use "$FOO" in the script, so the shell receives it as data.

**References**: https://docs.github.com/en/actions/security-for-github-actions/security-guides/security-hardening-for-github-actions#understanding-the-risk-of-script-injections

**AUD-2026-0005** · .github/workflows/triage.yml:13 · Confidence: high · Status: candidate · Engine: builtin-rules

~~~text
echo "New issue: ${{ github.event.issue.title }}"
~~~

### Dockerfile executes a remote script with curl \| sh — `dockerfile-curl-sh`

**HIGH** · Configuration / IaC · CWE-829 · A08:2021 · 1 location

**Description**: A downloaded script is executed without verification, so whoever controls the URL or the network path controls the build.

**Remediation**: Download a pinned version to a file, verify its SHA256, then run it; or vendor the installer.

**AUD-2026-0007** · Dockerfile:4 · Confidence: high · Status: candidate · Engine: builtin-rules

~~~text
RUN curl -fsSL https://example.com/install.sh | sh
~~~

### Possible hardcoded password or API key assignment — `secret-generic-assignment`

**HIGH** · Secrets · CWE-798 · A07:2021 · 1 location

**Description**: Possible plaintext credential detected; evidence is redacted in every report.

**Remediation**: Move credentials to environment variables or a secrets manager, rotate exposed values, and never commit plaintext credentials.

**AUD-2026-0012** · config/prod.env:3 · Confidence: medium · Status: candidate · Engine: builtin-secrets

~~~text
DB_PASSWORD="Tr*****************9x"
~~~

### Hard-coded SECRET\_KEY — `py-hardcoded-secret`

**HIGH** · Code · CWE-798 · A02:2021 · 1 location

**Description**: A literal SECRET\_KEY in source lets anyone with the code forge sessions and other signed data.

**Remediation**: Load SECRET\_KEY from the environment or a secret manager and rotate the committed value.

**AUD-2026-0008** · app/server.py:10 · Confidence: medium · Status: candidate · Engine: builtin-rules

~~~text
app.config["SECRET_KEY"] = "de************************e8"
~~~

### Python subprocess with shell=True and a command computed at runtime — `py-subprocess-shell`

**HIGH** · Code · CWE-78 · A03:2021 · 1 location

**Description**: A command that is not a string literal \(a variable, an f-string, a concatenation, % or .format\(\), or request data\) is run through a shell. Whatever reaches that value is parsed by the shell, so this form is reported even when the statement does not show where the value comes from.

**Remediation**: Pass an argument list and keep shell=False; never build shell strings from untrusted input.

**AUD-2026-0009** · app/server.py:41 · Confidence: medium · Status: candidate · Engine: builtin-rules

~~~text
return subprocess.run(command, shell=True, capture_output=True).stdout
~~~

### Python yaml.load with an unsafe loader — `py-yaml-load`

**HIGH** · Code · CWE-502 · A08:2021 · 1 location

**Description**: yaml.load without SafeLoader \(or yaml.unsafe\_load / full\_load\) can construct arbitrary Python objects from the document.

**Remediation**: Use yaml.safe\_load or pass Loader=yaml.SafeLoader.

**AUD-2026-0010** · app/server.py:51 · Confidence: medium · Status: candidate · Engine: builtin-rules

~~~text
return yaml.load(request.data, Loader=yaml.Loader)
~~~

### Web application run with debug enabled — `py-flask-debug`

**HIGH** · Code · CWE-489 · A05:2021 · 1 location

**Description**: debug=True starts the Werkzeug debugger, which gives anyone who can reach the port an interactive Python console.

**Remediation**: Take the debug flag from the environment, default it to off, and run production behind a WSGI server.

**AUD-2026-0011** · app/server.py:60 · Confidence: medium · Status: candidate · Engine: builtin-rules

~~~text
app.run(host="0.0.0.0", debug=True)
~~~

### Dockerfile does not declare a non-root user — `dockerfile-no-user`

**HIGH** · Configuration / IaC · CWE-250 · A05:2021 · 1 location

**Description**: No USER instruction and no privilege drop in the entrypoint, so the container process runs as root and a breakout yields root privileges.

**Remediation**: Create a dedicated user and add a USER instruction, for example USER 10001:10001.

**AUD-2026-0013** · Dockerfile:1 · Confidence: medium · Status: candidate · Engine: builtin-rules

~~~text
FROM python:latest
~~~

### Redirect to a URL from the request — `py-open-redirect`

**MEDIUM** · Code · CWE-601 · A01:2021 · 1 location

**Description**: The redirect target is read from the request, so a crafted link can send users to another site \(open redirect\).

**Remediation**: Validate the target against an allowlist or accept only relative paths; use url\_for with a fixed endpoint.

**AUD-2026-0014** · app/server.py:56 · Confidence: high · Status: candidate · Engine: builtin-rules

~~~text
return redirect(request.args["next"])
~~~

### Dockerfile uses the :latest base image tag — `dockerfile-latest-tag`

**LOW** · Configuration / IaC · CWE-1104 · A06:2021 · 1 location

**Description**: The latest tag is not reproducible and may pull unaudited changes.

**Remediation**: Pin an explicit version or digest, for example FROM node:22.11.0-bookworm-slim.

**AUD-2026-0015** · Dockerfile:1 · Confidence: high · Status: candidate · Engine: builtin-rules

~~~text
FROM python:latest
~~~

## 3. Dependency Vulnerabilities

> One row per vulnerable package version per lockfile. Dependency vulnerabilities come from lockfiles and OSV.dev; offline mode skips queries. The full per-advisory detail is in findings.json and results.sarif.

No reportable issues found.

## 4. Low-confidence candidates

> Active findings below the confidence threshold (medium). They are not counted in the summary and never affect the exit code at this threshold. `a → b` marks a confidence that the scan lowered. Full detail is in findings.json.

No low-confidence candidates.

## 5. Review hotspots

> These are uses of dangerous APIs, not confirmed vulnerabilities; a host agent or human should review them in context. Details are in the hotspots array of findings.json.

| Severity | Rule ID | Title | Count | Locations |
| --- | --- | --- | ---: | --- |
| high | py-sql-api | Python executes a SQL statement | 1 | app/server.py:29 |
| low | py-bind-all | Service bound to all interfaces | 1 | app/server.py:60 |

## 6. Suppressed findings

> These findings were suppressed by .code-audit-ignore or an inline code-audit:ignore comment. They remain in findings.json but are excluded from statistics and the exit code.

None.

## 7. Coverage and Limitations

| Languages | Files | LOC |
| --- | ---: | ---: |
| dockerfile | 1 | 7 |
| javascript | 1 | 16 |
| markdown | 2 | 397 |
| python | 1 | 61 |
| requirements | 1 | 4 |
| yaml | 1 | 14 |

- Scanned files: 8
- Skipped files: 0
- LOC: 504
- Generated lockfiles are used for SCA and high-confidence secret detection only; source rules skip them
- Scanned files in non-production paths: docs 2 — findings in these files have their confidence lowered (shown as `a → b`)

### Enabled engines

| Engine | Status | Detail |
| --- | --- | --- |
| builtin-rules | ok | 589 YAML rules, scanned 7 files |
| builtin-secrets | ok | scanned 8 text files |
| opengrep | disabled | not selected by --engines |
| osv-scanner | disabled | not selected by --engines |
| gitleaks | disabled | not selected by --engines |
| osv | offline | offline mode; queries skipped |

### Skipped files

No skipped files.

### Warnings

- offline mode: skipped OSV.dev queries \(3 dependencies were not checked for vulnerabilities\)

## 8. Appendix: Rules triggered in this run

> 589 rules were loaded; only the 15 that produced a finding or hotspot are listed. The complete rule list is in results.sarif (tool.driver.rules).

| Rule ID | Title | Severity | Confidence | CWE | Language | Hits |
| --- | --- | --- | --- | --- | --- | ---: |
| dockerfile-no-user | Dockerfile does not declare a non-root user | high | medium | CWE-250 | dockerfile | 1 |
| dockerfile-curl-sh | Dockerfile executes a remote script with curl \| sh | high | high | CWE-829 | dockerfile | 1 |
| dockerfile-latest-tag | Dockerfile uses the :latest base image tag | low | high | CWE-1104 | dockerfile | 1 |
| gha-script-injection | GitHub Actions script injection | high | high | CWE-94 | yaml | 1 |
| js-command-injection-request | Request data in a child\_process shell command | critical | high | CWE-78 | javascript, typescript | 1 |
| js-code-injection-request | Request data evaluated as JavaScript | critical | high | CWE-95 | javascript, typescript | 1 |
| py-flask-debug | Web application run with debug enabled | high | medium | CWE-489 | python | 1 |
| py-hardcoded-secret | Hard-coded SECRET\_KEY | high | medium | CWE-798 | python | 1 |
| py-bind-all | Service bound to all interfaces | low | low | CWE-1327 | python | 1 |
| py-sql-injection | Python SQL statement built with string formatting | critical | high | CWE-89 | python | 1 |
| py-sql-api | Python executes a SQL statement | high | low | CWE-89 | python | 1 |
| py-subprocess-shell | Python subprocess with shell=True and a command computed at runtime | high | medium | CWE-78 | python | 1 |
| py-insecure-deserialization | Python unpickles request data | critical | high | CWE-502 | python | 1 |
| py-yaml-load | Python yaml.load with an unsafe loader | high | medium | CWE-502 | python | 1 |
| py-open-redirect | Redirect to a URL from the request | medium | high | CWE-601 | python | 1 |

