# Demo application

A small, **deliberately vulnerable** project for trying code-audit: a Flask
service, a Node.js file, a Dockerfile, a GitHub Actions workflow, pinned old
dependencies and committed fake credentials. Do not deploy it. All credentials
in it are made up.

```sh
# from the repository root, after `pnpm install && pnpm build`
./bin/code-audit scan examples/demo-app --no-external --out /tmp/code-audit-demo
```

`--no-external` uses the built-in engines only, so the result does not depend
on which optional scanners you have installed. The dependency advisories come
from OSV.dev; add `--offline` to skip that lookup (the 8 advisory findings
then disappear and the report says the dependencies were not checked).

What the scan reports (22 findings, 1 low-confidence candidate, 2 hotspots):

| Where | What |
|---|---|
| `app/server.py:21` | SQL built with an f-string from a request parameter (critical) |
| `app/server.py:46` | `pickle.loads(request.data)` (critical) |
| `app/server.py:41` | `subprocess.run(command, shell=True)` with a computed command (high) |
| `app/server.py:51` | `yaml.load` with an unsafe loader (high) |
| `app/server.py:10`, `:60`, `:56` | hard-coded `SECRET_KEY`, `debug=True`, open redirect |
| `app/server.py:29` | hotspot only: the parameterized query is safe and is **not** a finding |
| `web/tools.js:8`, `:12` | command built by concatenation (critical); `eval` (low confidence) |
| `Dockerfile` | `curl ... \| sh` (critical), no `USER`, `latest` tag |
| `.github/workflows/triage.yml:13` | issue title interpolated into a `run:` script (high) |
| `config/prod.env` | AWS access key id and a password, both masked in every output |
| `requirements.txt` | flask 2.0.1, pyyaml 5.3.1, requests 2.19.1 with known advisories |

The complete Markdown report of one such run is in
[sample-report.md](sample-report.md).
