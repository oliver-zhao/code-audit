# code-audit

[English](README.md)

面向编程 agent 的代码安全审计插件，核心是一个确定性的扫描器。

`code-audit` 扫描本地项目里的漏洞、硬编码密钥、有风险的配置和带已知漏洞的依赖，把候选结果连同证据写成 Markdown、JSON 和 SARIF 报告。编程 agent（Claude Code、Codex、OpenCode、DSH）再通过 9 个 MCP 工具复核：读候选位置附近的代码、给出带理由的判定、补充扫描器漏掉的问题、生成最终报告。同一套流程也可以由人在命令行里完成，或者接入 CI。

扫描器本身不调用任何大模型，分工是有意设计的：

| 角色 | 负责 | 不负责 |
|---|---|---|
| **扫描器**（本工具） | 每次以相同方式找出候选、对密钥脱敏、统计哪些结果会让构建失败、把被扫描的仓库当作不可信输入 | 判断是否可达、是否可利用 |
| **复核者**（你的 agent 或你本人） | 读代码，凭证据确认或驳回每条候选，发现逻辑缺陷 | 悄悄决定：每一条驳回都会列在报告里 |

**它不是什么。** 它**不能证明代码没有漏洞**：扫描干净只说明这些引擎没有匹配到东西。结果是**候选**，多数规则一次只看一条语句。它不检测授权和业务逻辑缺陷、写在 HTML 模板文件里的 XSS、跨文件的数据流（见英文版 [Limits](README.md#limits)）。

本文是简介，完整的参数说明、安全模型和各宿主的细节以 [英文 README](README.md) 和 `docs/` 为准。

## 支持的语言和文件

下表的内容只需要 Node.js。`code-audit doctor` 会打印你当前版本的规则数量。

| 语言 / 文件类型 | 识别的文件 | 内置规则数 | 对照 [OSV.dev](https://osv.dev) 检查的依赖文件 |
|---|---|---:|---|
| **Python** | `.py`、`.pyw` | 102 | `requirements*.txt`（含 `-r` 引用）、`poetry.lock`、`uv.lock`、`pdm.lock`、`Pipfile.lock`、`pylock.toml` |
| **JavaScript / TypeScript** | `.js`、`.jsx`、`.mjs`、`.cjs`、`.ts`、`.tsx`、`.mts`、`.cts` | 67 | `package-lock.json`、`pnpm-lock.yaml` |
| **Java** | `.java`；Spring Boot 的 `application*.yml` / `bootstrap*.yml` | 78 | `pom.xml`（仅直接依赖且版本号为字面值） |
| **Go** | `.go` | 50 | `go.mod` |
| **C# / .NET** | `.cs`、Razor `.cshtml` / `.razor`、`web.config` 等 `*.config`、`appsettings*.json` | 57 | `packages.lock.json`、`*.csproj` / `*.fsproj` / `*.vbproj`（`PackageReference`）、`Directory.Build.props` / `.targets`、`Directory.Packages.props`、`packages.config` |
| **Rust** | `.rs` | 38 | `Cargo.lock`（结合 `Cargo.toml` 和 workspace 成员区分直接依赖与开发依赖） |
| **C / C++** | `.c`、`.h`、`.cc`、`.cpp`、`.cxx`、`.hpp`、`.hh`、`.hxx` | 46 | 无 |
| **Dockerfile** | `Dockerfile`、`Dockerfile.*`、`*.dockerfile` | 13 | |
| **Docker Compose** | compose 文件 | 10 | |
| **Kubernetes 清单** | 含 `apiVersion` 或 `securityContext` 的 `.yml`、`.yaml` | 26 | |
| **Terraform** | `.tf`、`.tfvars`（AWS、Azure、GCP） | 35 | |
| **GitHub Actions** | `.github/workflows/*.yml` | 18 | |
| **Agent 配置** | MCP 服务器配置、agent 设置和 hooks、`.codex/config.toml`、技能文件、指令文件（`CLAUDE.md`、`AGENTS.md`、`GEMINI.md`、`SKILL.md` 等，以及 `.cursorrules`、`.windsurfrules`、`.clinerules`、`.rules`、Cursor 的 `.mdc`） | 38 | |
| **依赖卫生** | `package.json`、Markdown、JSON、YAML、Dockerfile、shell 脚本（`.sh`、`.bash`、`.zsh`、`.ksh`）、requirements 文件、`.npmrc`、`.yarnrc`、`pip.conf`、`*.ini`、`*.cfg`、`uv.toml` | 11 | |
| **其他可识别的文件** | HTML 和模板（`.html`、`.jinja`、`.j2`、`.twig`、`.vue`、`.svelte`、`.ejs`、`.hbs` 等）、`.properties`、`.xml`（.NET 的 `*.config` 除外） | 0（计入覆盖统计，只做密钥检测） | |
| **密钥** | 所有文本文件 | 检测器，不计入规则数 | |

内置规则共 623 条：406 条报**结果**，217 条报**热点**（用了危险 API 但看不出攻击者能控制输入，供复核者阅读，不计入统计）。源代码按语句匹配，忽略注释，跨多行的调用当作一个整体：Python 按逻辑行（同时忽略文档字符串），C#、Java、JavaScript/TypeScript、Go、C/C++、Rust 由一个共用的 C 系词法分析器切分。规则覆盖注入（SQL、命令、代码、路径）、反序列化、SSRF 和重定向、响应里的 XSS、TLS、加密和硬编码密钥，按各语言主流库和框架的 API 编写（例如 Flask 和 Django、Express、Spring、net/http 和 gin、ASP.NET Core 和 EF Core、sqlx 和 diesel、OpenSSL 和 libcurl）。各语言的深度不同，Python 的规则最多。规则文件和匹配方式见 [docs/rules.md](docs/rules.md)。

装了 [Opengrep](https://github.com/opengrep/opengrep) 之后会多跑 47 条随附规则，其中 37 条是**数据流（taint）规则**，在同一个文件内跟踪请求数据流向 SQL、命令、路径、SSRF、模板、重定向、XSS、反序列化和 `eval` 等危险位置：Python 13 条（11 条 taint，Flask、Django、FastAPI），JavaScript/TypeScript 8 条（7），Java 7 条（6），Go 7 条（7），C# 6 条（5），C 4 条（1），Rust 2 条（用 `format!` 拼出的命令和 SQL）。

密钥检测覆盖私钥、云厂商令牌（AWS、GitHub、Slack 等）、URL 里的凭据、密码和密钥赋值，以及凭据文件（`.netrc`、`.pgpass`、`.npmrc`、`.pypirc`、Docker `auths`、kubeconfig）。密钥的值在所有输出里都会脱敏。

## 支持的 agent

`code-audit install --host <host>` 会为对应宿主写入项目内的配置。四个宿主都用真实模型端到端跑通过：从扫描到生成报告的完整审计，全程通过 MCP 工具，并按工具调用日志核对。

| Agent | 测试版本 | `--host` | 发起审计 |
|---|---|---|---|
| Claude Code | 2.1.332（macOS） | `claude-code` | 在项目里输入 `/audit`；无交互：`claude -p "/audit" --mcp-config .mcp.json --allowedTools "mcp__code-audit__*"` |
| Codex CLI | 0.171（macOS） | `codex` | 直接要求做安全审计；无交互用 `codex exec` 加上 `install` 打印出的三个 `-c` 参数 |
| OpenCode | 2.4.1（Linux） | `opencode` | `/audit`，或 `opencode run "Run a security audit of this project with the code-audit skill"`。新项目里先运行 `opencode mcp list`，等它显示 `code-audit` 已连接再开始：OpenCode 2.4.1 在此之前启动的会话里没有 MCP 服务器。 |
| DeepSeek Harness (DSH) | 0.2.2-rc.5（Linux） | `dsh` | `dsh <profile> --patch dsh/cordis.patch.yml`，然后要求做安全审计 |

其他支持 MCP 的 agent 可以直接使用标准输入输出的服务器 `code-audit-mcp`，工具和参数见 [docs/mcp.md](docs/mcp.md)。没有测过的：在 Claude Code 里交互式批准项目 MCP 服务器、通过插件市场安装 Claude Code 插件、Codex 的项目信任。各宿主细节见 `adapters/<host>/README.md`。

## 安装

要求：**Node.js 22 或更高**、git、pnpm（`corepack enable` 即可，或 `npm install -g pnpm`）。在 macOS 和 Linux 上测试过，Windows 没有测过。包还没有发布到 npm，需要从源码安装：

```sh
git clone https://github.com/oliver-zhao/code-audit.git
cd code-audit
corepack enable
pnpm install          # 首次构建前出现 "Failed to create bin" 警告可以忽略
pnpm build
export PATH="$PWD/bin:$PATH"    # bin/code-audit 和 bin/code-audit-mcp
```

把 `export` 那一行加进 shell 配置文件可以长期生效。检查安装：

```sh
code-audit doctor
```

```text
code-audit doctor (0.4.0)
Node.js: 24.22.1 OK
Rules: 623 built-in: 406 finding, 217 hotspot (<checkout>/rules)
Opengrep rules: 47 (<checkout>/rules/opengrep)
Active tier: Tier 0 + Tier 1
External tools (detection only, not invoked):
  opengrep       missing
  semgrep        missing
  osv-scanner    missing
  gitleaks       found  /opt/homebrew/bin/gitleaks (8.30.1)
```

**可选的扫描器。** 不装任何别的东西也能用。如果 `PATH` 里有 `opengrep`、`osv-scanner` 或 `gitleaks`，扫描时会一并运行并合并结果，`doctor` 会显示找到了哪些。code-audit 不会替你下载工具或规则包。

**更新：** `git pull && pnpm install && pnpm build`。**卸载：** 删除源码目录；装进项目的适配器文件用 `code-audit install --uninstall --host <host>` 移除。

## 使用

### 命令行

```sh
cd /path/to/project
code-audit scan .                      # 加 --offline 可跳过 OSV.dev 查询
```

结果写到项目内的 `.audit/<run-id>/`（请把 `.audit/` 加进 `.gitignore`），或用 `--out <dir>` 指定目录：

| 文件 | 用途 |
|---|---|
| `report.md` | 给人看：摘要、主要风险、每条结果的证据和修复建议 |
| `findings.json` | 完整数据：结果、热点、抑制、判定 |
| `results.sarif` | 给代码扫描工具（GitHub code scanning、IDE） |
| `coverage.json`、`run.json` | 扫了什么、没扫什么；本次运行的参数和统计 |

常用变体：

```sh
code-audit scan . --offline --no-external      # 只用内置引擎，不联网
code-audit scan . --fail-on critical           # 只有严重级别才让退出码为 1
code-audit scan . --since origin/main          # 只看某个 git 引用之后变更的文件
code-audit scan third-party/ --untrusted       # 审计别人的代码：不采纳它自带的任何忽略规则
code-audit scan . --lang zh                    # 中文报告
```

不用 agent 也能复核（`<run>` 是扫描打印的运行编号）：

```sh
code-audit findings <run> --severity high
code-audit read <run> app/server.py --start 15 --end 25
code-audit verdict <run> AUD-2026-0001 --status confirmed \
  --rationale "name comes from request.args and is formatted into the SQL text"
code-audit report <run> --format md            # report.md 现在带上了判定
```

### 在 agent 里使用

把适配器装进要审计的项目，然后让 agent 干活。`--absolute` 会写入本机 MCP 服务器的完整路径，不受 agent 启动时 `PATH` 的影响（生成的配置文件不要提交；不加这个参数时写入的是不带路径的 `code-audit-mcp`，适合提交）。

```sh
cd /path/to/project
code-audit install --host claude-code --absolute    # 或 codex | opencode | dsh
code-audit doctor --project .                       # 装了什么、MCP 命令能否找到
```

然后在 agent 里输入：

```text
/audit
```

或者直接说：“用 code-audit 技能对这个项目做一次安全审计并生成报告。” agent 会按 [skills/code-audit/SKILL.md](skills/code-audit/SKILL.md) 里的流程执行：

1. `audit_start` 启动扫描，`audit_status` 等待完成并取得统计
2. `audit_findings` 按风险从高到低列出候选
3. `audit_read` / `audit_search` 读取证据（密钥已脱敏，仓库内容标记为不可信）
4. `audit_verdict` 给出判定：`confirmed`、`likely`、`needs_review` 或 `false_positive`，每条都要写理由
5. `audit_add_finding` 补充规则漏掉的问题，或把热点提升为结果
6. `audit_report` 生成复核后的报告

`install` 只在项目目录内写文件，合并进已有配置时不会改写你的内容，`--dry-run` 可以先看计划。MCP 服务器只审计 agent 启动它时所在的目录。

### 在 CI 里使用

```sh
code-audit scan . --ci --format sarif,md --out audit-out --latest-link
```

提交一份 baseline 之后，只有**新增**的结果会让构建失败。baseline、SARIF 上传、GitHub 注解和增量扫描见英文版 [CI usage](README.md#ci-usage)。

### 审计不信任的仓库

默认情况下，扫描会采纳仓库对自己的说明（抑制文件、baseline、行内忽略注释、`tests/` 和 `vendor/` 目录名、开发依赖标记），这是团队在自己 CI 里想要的行为；每一项只要改变了结果，都会以 `WARNING` 报出。审计别人写的代码时，用 `--untrusted` 一次全部关掉。扫描器只读文件，不执行仓库代码，不安装依赖，不听从文件里的指令。详见 [docs/security-model.md](docs/security-model.md)。

## 示例

仓库里带了一个故意写了漏洞的小项目 [examples/demo-app](examples/demo-app)：一个 Flask 服务、一个 Node.js 文件、一个 Dockerfile、一个 GitHub Actions 工作流、固定了旧版本的依赖和假的凭据，共 6 个文件 107 行。扫描还会读到项目自己的 `README.md` 和提交在里面的示例报告，所以统计为 8 个文件。

```sh
code-audit scan examples/demo-app --offline --no-external --out /tmp/code-audit-demo
```

```text
code-audit scan completed: 20261127T143732Z-479f2b6d
Files: 8 scanned / 0 skipped, LOC 504
Rules: 623
Findings: 15 (critical 4, high 9, medium 1, low 1, info 0) at confidence >= medium
  by category: code 9, secrets 2, config/IaC 4, dependencies 0
Low-confidence candidates: 0 (not counted above)
Hotspots: 2 (not counted above)
Exit code: 1 - 13 findings count toward the exit code (severity >= high, confidence >= medium)
Duration: 171 ms
Report directory: /tmp/code-audit-demo/20261127T143732Z-479f2b6d
warning: offline mode: skipped OSV.dev queries (3 dependencies were not checked for vulnerabilities)
```

退出码是 1，因为有结果达到了阈值，这正是这个示例的预期结果。15 条里的几条：

| 结果 | 位置 | 规则 |
|---|---|---|
| 用 f-string 把请求参数拼进 SQL | `app/server.py:21` | `py-sql-injection`（严重） |
| `pickle.loads(request.data)` | `app/server.py:46` | `py-insecure-deserialization`（严重） |
| 把请求参数拼进 shell 命令 | `web/tools.js:8` | `js-command-injection-request`（严重） |
| 把请求参数交给 `eval` | `web/tools.js:12` | `js-code-injection-request`（严重） |
| 构建镜像时 `curl ... \| sh` | `Dockerfile:4` | `dockerfile-curl-sh`（高） |
| 把 issue 标题插进 `run:` 脚本 | `.github/workflows/triage.yml:13` | `gha-script-injection`（高） |
| AWS access key id | `config/prod.env:4` | `secret-aws-access-key`（高） |

`app/server.py:29` 的参数化查询**不是**结果：它只作为热点列给复核者，不计入统计。因为加了 `--offline`，`requirements.txt` 里固定的三个依赖（flask 2.0.1、pyyaml 5.3.1、requests 2.19.1）只列出、不检查，警告里会说明这一点。去掉 `--offline` 就会对照 OSV.dev 检查它们，报出的公告取决于当天的漏洞数据。

测试样例里的安全对照组会得到另一种结果：

```sh
code-audit scan fixtures/clean --offline --no-external --out /tmp/code-audit-clean
```

```text
Findings: 0 (critical 0, high 0, medium 0, low 0, info 0) at confidence >= medium
Exit code: 0 - 0 findings count toward the exit code (severity >= high, confidence >= medium)
```

## 报告示例

上面这次运行的完整 `report.md` 提交在 [examples/demo-app/sample-report.md](examples/demo-app/sample-report.md)（359 行，英文；加 `--lang zh` 可以生成中文报告）。报告开头是哪些结果会让构建失败以及主要风险：

```markdown
**13 findings count toward the exit code** (severity ≥ high, confidence ≥ medium); a scan with these thresholds exits 1.

| Category | Critical | High | Medium | Low | Info | Total |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Code | 4 | 4 | 1 | 0 | 0 | 9 |
| Secrets | 0 | 2 | 0 | 0 | 0 | 2 |
| Configuration / IaC | 0 | 3 | 0 | 1 | 0 | 4 |
| Dependencies (advisories) | 0 | 0 | 0 | 0 | 0 | 0 |
| **Total** | **4** | **9** | **1** | **1** | **0** | **15** |
```

接着按规则分组列出每条结果，包含 CWE 编号、说明、修复建议和匹配到的那一行；联网查询 OSV.dev 时，依赖按 “包 @ 版本” 聚合，给出公告数量、最高严重程度和建议升级版本；之后是低置信度候选、热点、被抑制的结果、被复核驳回的结果、覆盖范围与局限、触发的规则。agent 或人复核之后，每条结果会显示判定，封面会写明复核了多少条。

各个数字的含义：

| 数字 | 统计的是什么 |
|---|---|
| **结果**（头条数字） | 置信度不低于 `--min-confidence`（默认 `medium`）的有效结果 |
| **低置信度候选** | 置信度低于该阈值的有效结果，单独列出，不计入退出码 |
| **热点** | 用了危险 API 但看不出攻击者能控制输入，供复核者阅读，从不计数 |
| **被抑制 / 误报** | 不计入上面的数字，但都会列在报告里 |

## 退出码

| 退出码 | 含义 |
|---|---|
| `0` | 扫描完成，没有结果达到阈值 |
| `1` | 至少有一条结果计入：有效（未被抑制、未被判为误报）、严重程度不低于 `--fail-on`、置信度不低于 `--min-confidence`，并且在使用 baseline 时是新增的 |
| `2` | 运行错误：参数错误、路径不存在、抑制文件或 baseline 无效、规则加载失败、写入被拒绝 |

## 测试

```sh
pnpm test                   # 先构建，再跑全部测试（需要几分钟）
pnpm exec vitest run packages/core/test/rules.test.ts     # 开发时只跑一个文件
```

约 1190 个测试，在 CI 里跑 Node 22 和 24、Linux 和 macOS 四种组合。主要覆盖：

- **规则**：`fixtures/vulnerable/` 为每条规则埋了一处漏洞，[EXPECTED.json](fixtures/vulnerable/EXPECTED.json) 列出每一处的规则、文件和行号，必须全部报出；`fixtures/clean/` 是写法相似但安全的对照，必须**一条都不报**。Python 和 C# 的规则文件做双向检查：没有列出的结果也不允许出现。各语言的规则测试（`packages/core/test/rules-*.test.ts`）另外覆盖反例和跨行写法。
- **规则开销**：每个规则文件里的每个正则都要在病态输入下限时跑完，会灾难性回溯的规则无法通过。
- **依赖**：lockfile 解析器用真实格式的样例测试；漏洞查询通过注入的 HTTP 客户端和录制的数据进行，单元测试不联网。
- **外部扫描器**：用假的可执行文件回放 Opengrep、OSV-Scanner、Gitleaks 的真实输出；真实工具存在于 `.tools/bin` 时另有一组测试实际运行它们。
- **恶意仓库**：路径逃逸（符号链接、`..`、大小写）、预置的运行目录和清单、仓库里的 git 配置、畸形的 lockfile 和 JSON、通过文件名注入 Markdown、密钥是否出现在任何输出渠道。
- **命令行、MCP、安装器**：命令以真实进程运行；MCP 服务器通过标准输入输出驱动；`install` / `--uninstall` 在带有用户已有配置的临时项目上运行。
- **一致性**：同一次运行在报告、SARIF、JSON、命令行、CI 和 MCP 摘要里的数字必须相同；`--help` 和 README 里的参数、规则格式、文档里的 MCP 工具都与代码自动比对。

手动试一下样例：

```sh
code-audit scan fixtures/vulnerable --offline --no-external --no-ignore-file --out /tmp/ca-vulnerable   # 退出码 1
code-audit scan fixtures/clean      --offline --no-external --out /tmp/ca-clean                          # 退出码 0
```

早期版本在公开项目（flask、requests、httpie 和四个故意留漏洞的靶场）上的表现，以及每轮审查发现的问题，记录在阶段报告 [docs/M4_REPORT.md](docs/M4_REPORT.md) 和 [docs/PY1_REPORT.md](docs/PY1_REPORT.md) 里；此后的变化见 [CHANGELOG.md](CHANGELOG.md)。

## 局限

- 内置规则一次只匹配一条语句。Python 按逻辑行切分；C#、Java、JavaScript/TypeScript、Go、C/C++、Rust 由共用的 C 系词法分析器按语句切分；Dockerfile 按指令切分（含 `\` 续行）；跨行的 XML 开始标签算一个单元。其他文件类型（YAML、JSON、Terraform、shell、Markdown、Razor 等）逐行匹配，Terraform 的 HCL 不做解析。词法分析器分不清代码和字符串时（字符串没闭合、文件在注释或括号里结束），会放宽处理：该区域按普通行匹配，并给出警告。规则不跨语句、跨文件跟踪数据。Opengrep 数据流规则只在单个文件内跟踪，并且不经过类方法。
- 不覆盖：授权与业务逻辑、竞态条件、密码学设计，以及任何需要运行代码才能发现的问题。XSS 只覆盖 C# 和 Razor 视图，以及 Go、Java、JavaScript、Python、Rust 里直接写入响应的情况，不覆盖一般的 HTML 模板文件：模板（`.html`、`.jinja`、`.vue`、`.svelte` 等）能识别但没有规则，Vue 和 Svelte 文件里的 `<script>` 也不会当作 JavaScript 分析。Spring Boot 配置只检查 `application*.yml` / `bootstrap*.yml`，不检查 `.properties` 文件。
- 依赖结果取决于 lockfile 或固定的版本号，没有固定版本的条目在警告中计数。`pom.xml` 只读取版本号为字面值的直接依赖。没有自己 `packages.lock.json` 的 NuGet 项目只检查直接引用；版本范围、浮动版本和无法解析的 MSBuild 属性只在警告中计数，不做检查。来自 git 仓库或非 crates.io 仓库的 crate 只在警告中计数，不做检查。`yarn.lock`、`go.sum`、`composer.lock` 内置引擎不解析。
- 名为 `bin` 的目录默认不扫描（和 `build`、`dist`、`vendor` 等一样），Cargo 的 `src/bin` 除外；`--untrusted` 会读取它们。
- Semgrep 作为 Opengrep 的替代被支持，但从未在测试中实际运行过。
- Windows 没有测试过。

本版本的变化和已知局限见 [CHANGELOG.md](CHANGELOG.md)（0.4.0）。在公开项目上的实测结果和当时发现的已知局限记录在早期开发阶段的报告 [docs/M4_REPORT.md](docs/M4_REPORT.md) 和 [docs/PY1_REPORT.md](docs/PY1_REPORT.md) 里，其中的数字早于 0.3.0。

## 许可证

[Apache License 2.0](LICENSE)。Copyright 2026 The code-audit Authors，见 [NOTICE](NOTICE)。

- 可以按许可证条款使用、修改和再分发，包括商业用途。不提供任何担保：扫描结果不是安全保证。
- **规则。** 所有内置规则和随附的 Opengrep 语法规则都是为本项目编写的，适用同一许可证。不包含也不下载 Semgrep registry 规则、Bandit 规则或其他第三方规则包。
- **可选扫描器不随本项目分发。** Opengrep、Semgrep、OSV-Scanner、Gitleaks 是各自独立的程序，适用它们自己的许可证；code-audit 只在你自己安装了它们的情况下调用。
- **依赖。** 生产依赖不允许使用 GPL、AGPL、LGPL 许可证，`pnpm run check:licenses` 在 CI 里强制检查。
- **漏洞数据** 在扫描时取自 [OSV.dev](https://osv.dev)，受其上游各漏洞库的许可证约束。
