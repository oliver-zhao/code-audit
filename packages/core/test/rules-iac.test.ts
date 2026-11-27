/**
 * Infrastructure-as-code rules: Dockerfile, Compose, Kubernetes, Terraform and
 * GitHub Actions (rules/iac/*.yml).
 */
import path from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { inventory } from "../src/inventory.js";
import { MAX_PATTERN_LINE_LENGTH, loadRules, scanRules } from "../src/rules.js";
import { yamlKeyValues } from "../src/yamlValues.js";
import { CLEAN, RULES_DIR, VULNERABLE, cleanup, loadExpected, makeTempDir, writeFile } from "./helpers.js";

const temp = makeTempDir("rules-iac");
afterAll(() => cleanup(temp));

const ruleSet = loadRules(RULES_DIR);
const IAC_RULE = /^(?:dockerfile|compose|k8s|tf|gha)-/;
const IAC_FILE = /^(?:iac\/|\.github\/workflows\/)/;

let counter = 0;
/** Scans one throw-away project and returns "line ruleId kind" for IaC rules. */
function scan(files: Record<string, string>, only?: RegExp): string[] {
  counter += 1;
  const root = path.join(temp, `p${counter}`);
  for (const [relative, content] of Object.entries(files)) writeFile(root, relative, content);
  const result = scanRules(inventory(root).files, ruleSet, { inlineIgnore: false });
  return result.hits
    .filter((hit) => IAC_RULE.test(hit.rule.id) && (only === undefined || only.test(hit.rule.id)))
    .map((hit) => `${hit.file.relPath}:${hit.line} ${hit.rule.id}`)
    .sort();
}
const lines = (...text: string[]): string => `${text.join("\n")}\n`;

describe("IaC fixtures", () => {
  it("reports exactly the IaC seeds of EXPECTED.json, with their kind", () => {
    const expected = loadExpected()
      .seeds.filter((seed) => IAC_RULE.test(seed.ruleId) && IAC_FILE.test(seed.file))
      .map((seed) => `${seed.file}:${seed.line} ${seed.ruleId} ${seed.kind ?? "finding"}`)
      .sort();
    const reported = scanRules(inventory(VULNERABLE).files, ruleSet, { inlineIgnore: false })
      .hits.filter((hit) => IAC_RULE.test(hit.rule.id) && IAC_FILE.test(hit.file.relPath))
      .map((hit) => `${hit.file.relPath}:${hit.line} ${hit.rule.id} ${hit.rule.kind}`)
      .sort();
    expect(reported).toEqual(expected);
    expect(reported.length).toBeGreaterThan(100);
  });

  it("has a seed for every IaC rule in the IaC fixtures", () => {
    const seeded = new Set(loadExpected().seeds.map((seed) => seed.ruleId));
    const iacRules = ruleSet.rules.filter((rule) => rule.sourceFile.startsWith(`iac${path.sep}`));
    expect(iacRules.length).toBeGreaterThan(90);
    expect(iacRules.map((rule) => rule.id).filter((id) => !seeded.has(id))).toEqual([]);
    for (const rule of iacRules) expect(rule.id).toMatch(IAC_RULE);
  });

  it("finds nothing but three low-confidence hotspots in the clean IaC fixtures", () => {
    const hits = scanRules(inventory(path.join(CLEAN, "iac")).files, ruleSet, { inlineIgnore: false }).hits.filter(
      (hit) => IAC_RULE.test(hit.rule.id),
    );
    expect(hits.map((hit) => `${hit.file.relPath}:${hit.line} ${hit.rule.id}`).sort()).toEqual([
      "kubernetes/chart/templates/deployment.yaml:8 k8s-capabilities-not-dropped",
      "kubernetes/pod.yml:31 k8s-secret-in-env",
      "terraform/main.tf:17 tf-sg-open-ssh",
    ]);
    for (const hit of hits) {
      expect(hit.rule.kind).toBe("hotspot");
      expect(hit.rule.confidence).toBe("low");
    }
  });
});

describe("Dockerfile rules", () => {
  it("reports root only when no other user follows, and no USER only for images that run something", () => {
    expect(
      scan({
        "a/Dockerfile": lines("FROM debian:12.7", "USER root", "RUN apt-get update", "USER app"),
        "b/Dockerfile": lines("FROM debian:12.7", "USER 0:0"),
        "c/Dockerfile": lines("FROM debian:12.7", "RUN apt-get install -y gosu", 'ENTRYPOINT ["gosu", "app", "run"]'),
        "d/Dockerfile": lines("FROM gcr.io/distroless/static-debian12:nonroot", 'CMD ["/app"]'),
        "e/Dockerfile": lines("FROM buildpack-deps:bookworm", 'CMD ["python3"]'),
        "f/Dockerfile": lines("FROM golang:1.23 AS build", "FROM build AS test", "FROM alpine:3.20 AS runtime", 'CMD ["/app"]'),
      }, /user/),
    ).toEqual([
      "b/Dockerfile:2 dockerfile-user-root",
      "f/Dockerfile:3 dockerfile-no-user",
    ]);
  });

  it("does not take a build-stage reference for an untagged image", () => {
    expect(
      scan({
        Dockerfile: lines(
          "FROM golang:1.23 AS builder",
          "FROM builder",
          "FROM scratch",
          "FROM ${BASE_IMAGE}",
          "FROM ubuntu",
          "FROM --platform=$BUILDPLATFORM quay.io/org/tool AS tool",
          "FROM registry.example.com:5000/team/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
          "FROM node:latest",
          "USER app",
        ),
      }, /tag/),
    ).toEqual([
      "Dockerfile:5 dockerfile-untagged-base-image",
      "Dockerfile:6 dockerfile-untagged-base-image",
      "Dockerfile:8 dockerfile-latest-tag",
    ]);
  });

  it("does not report verified downloads, parsing of JSON output or comments", () => {
    expect(
      scan({
        Dockerfile: lines(
          "FROM alpine:3.20",
          "# RUN curl https://example.invalid/i.sh | sh",
          'RUN curl -fsSL https://example.invalid/t.tgz -o t.tgz && echo "abc  t.tgz" | sha256sum -c -',
          "RUN curl -fsSL https://api.example.invalid/x | python3 -c 'import json,sys; print(json.load(sys.stdin))'",
          "RUN curl -fsSL https://example.invalid/x | shasum -a 256",
          "RUN curl -K /etc/curl.conf https://example.invalid/a -o a",
          'RUN echo "deb [ trusted=yes ] file:///tmp/repo ./" > /etc/apt/sources.list.d/local.list',
          "ADD --checksum=sha256:abc https://example.invalid/a.tgz /a.tgz",
          "RUN chmod 1777 /tmp && chmod 0755 /app",
          "RUN apt-get purge -y sudo",
          "EXPOSE 2222 8022",
          "USER app",
        ),
      }),
    ).toEqual([]);
  });

  it("reports interpreters fed by a download, in every spelling", () => {
    expect(
      scan({
        Dockerfile: lines(
          "FROM alpine:3.20",
          "RUN curl -sSL https://example.invalid/i.sh | sudo -E bash -s -- --yes",
          'RUN sh -c "$(curl -fsSL https://example.invalid/i.sh)"',
          "RUN bash <(wget -qO- https://example.invalid/i.sh)",
          "RUN curl -sSL https://example.invalid/get-pip.py | python3",
          "USER app",
        ),
      }, /curl-sh/),
    ).toEqual(["Dockerfile:2 dockerfile-curl-sh", "Dockerfile:3 dockerfile-curl-sh", "Dockerfile:4 dockerfile-curl-sh", "Dockerfile:5 dockerfile-curl-sh"]);
  });

  it("reports literal secrets in ENV and ARG but not references, files or flags", () => {
    expect(
      scan({
        Dockerfile: lines(
          "FROM alpine:3.20",
          "ENV DB_PASSWORD=hunter2hunter2",
          "ENV MYSQL_PASSWORD legacy-form-secret",
          "ARG GITHUB_TOKEN",
          "ENV GITHUB_TOKEN=${GITHUB_TOKEN}",
          "ENV DB_PASSWORD_FILE=/run/secrets/db",
          "ENV SECRET_KEY=/run/secrets/key",
          "ENV TOKENIZERS_PARALLELISM=false",
          "ENV ALLOW_EMPTY_PASSWORD=yes",
          "ENV API_KEY=changeme",
          "USER app",
        ),
      }, /secret/),
    ).toEqual(["Dockerfile:2 dockerfile-secret-env", "Dockerfile:3 dockerfile-secret-env"]);
  });

  it.todo(
    "sees `curl ... \\` followed by `| sh` on the next line (a RUN continued with a backslash is several lines today)",
  );
});

describe("Compose rules", () => {
  it("matches capabilities only under cap_add, and ports only under ports", () => {
    expect(
      scan({
        "docker-compose.override.yml": lines(
          "services:",
          "  a:",
          "    image: x/y:1",
          "    cap_drop: [ALL, SYS_ADMIN]",
          "    cap_add: [CAP_SYS_ADMIN]",
          "    expose:",
          '      - "5432"',
          "    ports:",
          '      - "127.0.0.1:5432:5432"',
          '      - "0.0.0.0:6379:6379"',
          "      - target: 27017",
          "        published: 27017",
        ),
      }),
    ).toEqual([
      "docker-compose.override.yml:10 compose-db-port-public",
      "docker-compose.override.yml:11 compose-db-port-public",
      "docker-compose.override.yml:12 compose-db-port-public",
      "docker-compose.override.yml:5 compose-cap-add-critical",
    ]);
  });

  it("ignores comments, read-only single files, substitutions and secret files", () => {
    expect(
      scan({
        "compose.yaml": lines(
          "services:",
          "  a:",
          "    image: x/y:1",
          "    # privileged: true",
          "    # network_mode: host",
          "    volumes:",
          "      - /etc/localtime:/etc/localtime:ro",
          "      - /etc/ssl/certs:/etc/ssl/certs:ro",
          "    environment:",
          "      - DB_PASSWORD=${DB_PASSWORD:-x}",
          "      - DB_PASSWORD_FILE=/run/secrets/db",
          "      - MYSQL_ALLOW_EMPTY_PASSWORD=yes",
          "      - GRAFANA_PASSWORD=/run/secrets/grafana",
          "      SESSION_SECRET: <set-me>",
        ),
      }),
    ).toEqual([]);
  });

  it("only applies to Compose file names", () => {
    expect(scan({ "deploy/values.yml": lines("privileged: true", "network_mode: host") }, /compose/)).toEqual([]);
  });
});

describe("Kubernetes rules", () => {
  const POD = ["apiVersion: v1", "kind: Pod", "metadata:", "  name: p", "spec:"];

  it("does not take a probe path for a hostPath, nor a dropped capability for an added one", () => {
    expect(
      scan({
        "manifests/p.yaml": lines(
          ...POD,
          "  containers:",
          "    - name: a",
          "      image: a/b:1",
          "      livenessProbe:",
          "        httpGet:",
          "          path: /",
          "      securityContext:",
          "        capabilities:",
          "          drop: [ALL, SYS_ADMIN]",
          "      resources:",
          "        limits: {memory: 64Mi}",
          "  volumes:",
          "    - name: logs",
          "      hostPath:",
          "        path: /var/log",
        ),
      }),
    ).toEqual([]);
  });

  it("applies to any manifest with an apiVersion, not only to k8s/ folders", () => {
    expect(scan({ "apps/web/pod.yaml": lines(...POD, "  hostNetwork: true") }, /host-network/)).toEqual([
      "apps/web/pod.yaml:6 k8s-host-network",
    ]);
    // Not a Kubernetes file.
    expect(scan({ "config/app.yaml": lines("hostNetwork: true", "privileged: true") }, /^k8s-/)).toEqual([]);
  });

  it("reads hostPath values written in any YAML form", () => {
    expect(
      scan({
        "k8s/ds.yaml": lines(
          ...POD,
          "  volumes:",
          "    - {name: root, hostPath: {path: /, type: Directory}}",
          '    - name: sock',
          "      hostPath:",
          '        path: "/run/containerd/containerd.sock"',
        ),
      }, /hostpath/),
    ).toEqual(["k8s/ds.yaml:10 k8s-hostpath-mount", "k8s/ds.yaml:7 k8s-hostpath-mount"]);
  });

  it("only reports node-wide sysctls and RBAC words under their keys", () => {
    expect(
      scan({
        "k8s/s.yaml": lines(
          ...POD,
          "  securityContext:",
          "    sysctls:",
          "      - {name: net.ipv4.ip_local_port_range, value: '1024 65000'}",
          "      - {name: kernel.msgmax, value: '65536'}",
          "      - {name: kernel.core_pattern, value: '|/tmp/x'}",
        ),
        "k8s/r.yaml": lines(
          "apiVersion: rbac.authorization.k8s.io/v1",
          "kind: Role",
          "metadata:",
          "  name: bind-reader",
          "  annotations: {note: '*'}",
          "rules:",
          '  - resources: ["rolebindings"]',
          '    verbs: ["get"]',
        ),
      }),
    ).toEqual(["k8s/s.yaml:10 k8s-unsafe-sysctl"]);
  });

  it("reports Secret data at the top level only", () => {
    expect(
      scan({
        "k8s/secret.yaml": lines(
          "apiVersion: v1",
          "kind: Secret",
          "metadata:",
          "  name: database-credentials",
          "  namespace: production-env",
          "type: Opaque",
          "stringData:",
          "  password: s3cr3t-value-123",
        ),
      }, /secret/),
    ).toEqual(["k8s/secret.yaml:8 k8s-secret-literal-data"]);
  });
});

describe("Terraform rules", () => {
  it("applies to every .tf and .tfvars file and skips comments", () => {
    expect(
      scan({
        "main.tf": lines("# publicly_accessible = true", "// acl = \"public-read\"", "publicly_accessible = true"),
        "envs/prod.tfvars": lines('db_password = "Wint3rIsC0ming2024"'),
      }),
    ).toEqual(["envs/prod.tfvars:1 tf-hardcoded-credentials", "main.tf:3 tf-rds-publicly-accessible"]);
  });

  it("reports Action \"*\" but not Resource \"*\" alone, nor NotAction", () => {
    expect(
      scan({
        "iam.tf": lines(
          'actions   = ["ec2:DescribeInstances"]',
          'resources = ["*"]',
          'not_actions = ["*"]',
          '"NotAction": "*",',
          '"Action": "*",',
          'Action = ["*"]',
        ),
      }, /tf-iam-wildcard/),
    ).toEqual(["iam.tf:5 tf-iam-wildcard", "iam.tf:6 tf-iam-wildcard"]);
  });

  it("does not report references or secret metadata as secrets", () => {
    expect(
      scan({
        "lambda.tf": lines(
          "API_KEY = var.api_key",
          'CLIENT_SECRET = "${var.client_secret}"',
          "secret_arn = aws_secretsmanager_secret.x.arn",
          'KMS_SECRET = "arn:aws:kms:us-east-1:111122223333:key/abcd"',
          'secret_name = "prod/db/credentials"',
          'api_key = "example-key-value"',
        ),
      }, /secret|credential/),
    ).toEqual([]);
  });

  it("only reports SSH and RDP ports when the file opens a CIDR to everyone", () => {
    const rule = (cidr: string) =>
      lines('resource "aws_security_group" "a" {', "  ingress {", "    from_port = 22", "    to_port = 22", `    cidr_blocks = ["${cidr}"]`, "  }", "}");
    expect(scan({ "a.tf": rule("10.0.0.0/8") }, /admin-port/)).toEqual([]);
    expect(scan({ "a.tf": rule("0.0.0.0/0") }, /admin-port/)).toEqual(["a.tf:3 tf-sg-admin-port-open"]);
  });

  it.todo(
    "correlates an open CIDR with port 22 in the same block (a block spanning lines is not seen as a whole today)",
  );
  it.todo(
    "sees a secret default in a multi-line `variable \"db_password\" { ... default = \"...\" }` block",
  );
});

describe("GitHub Actions rules", () => {
  const W = ".github/workflows/w.yml";

  it("reports checkout of the pull request head only in privileged workflows", () => {
    const steps = [
      "jobs:",
      "  a:",
      "    runs-on: ubuntu-latest",
      "    permissions: {contents: read}",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          ref: ${{ github.event.pull_request.head.sha }}",
      "          persist-credentials: false",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          ref: refs/pull/${{ github.event.issue.number }}/merge",
      "          persist-credentials: false",
    ];
    expect(scan({ [W]: lines("on: pull_request", ...steps) }, /checkout/)).toEqual([]);
    expect(scan({ [W]: lines("on: issue_comment", ...steps) }, /checkout/)).toEqual([
      `${W}:13 gha-untrusted-checkout`,
      `${W}:9 gha-untrusted-checkout`,
    ]);
  });

  it("does not report the trigger name in a condition or a comment", () => {
    expect(
      scan({
        [W]: lines(
          "# pull_request_target is not used here",
          "on: [push, pull_request]",
          "jobs:",
          "  a:",
          "    if: github.event_name != 'pull_request_target'",
          "    runs-on: ubuntu-latest",
          "    steps:",
          "      - uses: actions/checkout@v4",
        ),
      }, /pull-request-target/),
    ).toEqual([]);
    expect(scan({ [W]: lines("on: [push, pull_request_target]", "jobs: {a: {runs-on: x, steps: [{uses: actions/checkout@v4}]}}") }, /pull-request-target/)).toEqual([
      `${W}:1 gha-pull-request-target`,
    ]);
  });

  it("treats SHA-pinned, GitHub-owned, local and Docker actions as pinned", () => {
    expect(
      scan({
        [W]: lines(
          "on: push",
          "permissions: {}",
          "jobs:",
          "  a:",
          "    runs-on: ubuntu-latest",
          "    steps:",
          "      - uses: actions/setup-node@v4",
          "      - uses: github/codeql-action/init@v3",
          "      - uses: ./.github/actions/local",
          "      - uses: docker://alpine:3.20",
          "      - uses: org/action@0123456789abcdef0123456789abcdef01234567",
          "      - uses: org/action/sub@main",
          "  b:",
          "    uses: org/repo/.github/workflows/x.yml@v1",
        ),
      }, /unpinned/),
    ).toEqual([`${W}:12 gha-unpinned-action`, `${W}:14 gha-unpinned-action`]);
  });

  it("writes to GITHUB_ENV: a direct expression is critical, a constant is nothing", () => {
    expect(
      scan({
        [W]: lines(
          "on: issues",
          "permissions: {}",
          "jobs:",
          "  a:",
          "    runs-on: ubuntu-latest",
          "    steps:",
          '      - run: echo "T=${{ github.event.issue.title }}" >> "$GITHUB_ENV"',
          '      - run: echo "MODE=release" >> "$GITHUB_ENV"',
          '      - run: echo "T=${{ github.event.issue.title }}"',
        ),
      }, /env|injection/),
    ).toEqual([`${W}:7 gha-github-env-injection`, `${W}:9 gha-script-injection`]);
  });

  it("does not report curl | sh outside run, nor a curl whose output is checked", () => {
    expect(
      scan({
        [W]: lines(
          "on: push",
          "permissions: {}",
          "jobs:",
          "  a:",
          "    runs-on: ubuntu-latest",
          "    steps:",
          "      - name: curl https://x | sh is described here",
          "        run: curl -fsSL https://example.invalid/x.tgz -o x.tgz && sha256sum -c x.sha256",
        ),
      }, /curl/),
    ).toEqual([]);
  });
});

describe("engine points the IaC rules rely on", () => {
  it("tests a filePattern in the windows of an over-long line instead of failing open", () => {
    const long = `description: "${"x".repeat(MAX_PATTERN_LINE_LENGTH * 3)}"`;
    // No apiVersion anywhere: the Kubernetes rules stay off despite the long line.
    expect(scan({ "cfn/a.yaml": lines(long, "privileged: true") }, /^k8s-/)).toEqual([]);
    // `apiVersion:` in the middle of a long line is not a line start.
    expect(scan({ "cfn/b.yaml": lines(`x: ${"y ".repeat(1500)}  apiVersion: v1`, "privileged: true") }, /^k8s-/)).toEqual([]);
    // A filePattern met only beyond the first window is still found.
    const rule = (name: string) =>
      lines(`${"#".repeat(MAX_PATTERN_LINE_LENGTH + 10)} uses: actions/checkout@v4`, "on: pull_request_target", "jobs: {}");
    expect(scan({ ".github/workflows/w.yml": rule("w") }, /pull-request-target/)).toEqual([
      ".github/workflows/w.yml:2 gha-pull-request-target",
    ]);
  });

  it("compares withinKeys keys case-sensitively", () => {
    const parsed = yamlKeyValues("Resources:\n  Role: '*'\nrules:\n  - resources: ['*']\n", ["resources"]);
    expect(parsed.ok).toBe(true);
    if (parsed.ok) expect(parsed.values.map((value) => `${value.key}=${value.text}`)).toEqual(["resources=*"]);
  });
});

describe("review fixes", () => {
  it("keeps CloudFormation, kind, skaffold and Ansible files out of the Kubernetes rules", () => {
    expect(
      scan({
        "cfn/t.yaml": lines(
          'AWSTemplateFormatVersion: "2010-09-09"',
          "Resources:",
          "  R:",
          "    Type: AWS::IAM::Role",
          "    Properties:",
          "      securityContext: {privileged: true}",
          "      resources: ['*']",
        ),
        "kind/cluster.yaml": lines("kind: Cluster", "apiVersion: kind.x-k8s.io/v1alpha4", "nodes:", "  - role: control-plane", "    extraMounts:", "      - hostPath: /", "        containerPath: /host"),
        "skaffold.yaml": lines("apiVersion: skaffold/v4beta6", "kind: Config", "deploy:", "  docker:", "    images: [app]", "privileged: true"),
        "ansible/site.yml": lines("- hosts: all", "  tasks:", "    - k8s:", "        definition:", "          apiVersion: v1", "          spec: {hostNetwork: true}"),
      }, /^k8s-/),
    ).toEqual([]);
  });

  it("does not take a probe path for a mount when a Helm template falls back to lines", () => {
    expect(
      scan({
        "chart/templates/ds.yaml": lines(
          "apiVersion: apps/v1",
          "kind: DaemonSet",
          "metadata: {name: {{ .Release.Name }}}",
          "spec:",
          "  template:",
          "    spec:",
          "      containers:",
          "        - livenessProbe:",
          "            httpGet:",
          "              path: /",
          "      volumes:",
          "        - name: sock",
          "          hostPath:",
          "            path: /var/run/docker.sock",
        ),
      }, /hostpath/),
    ).toEqual(["chart/templates/ds.yaml:14 k8s-hostpath-mount"]);
  });

  it("reads flow-style security contexts", () => {
    expect(
      scan({ "k8s/p.yaml": lines("apiVersion: v1", "kind: Pod", "spec:", "  hostNetwork: false", "  securityContext: {runAsUser: 0, allowPrivilegeEscalation: true}") }, /run-as-root|escalation/),
    ).toEqual(["k8s/p.yaml:5 k8s-allow-privilege-escalation", "k8s/p.yaml:5 k8s-run-as-root"]);
  });

  it("gates GitHub triggers on the declaration, not on the word", () => {
    const body = [
      "jobs:",
      "  a:",
      "    if: github.event_name == 'workflow_run' || github.event_name == 'issue_comment'",
      "    runs-on: ubuntu-latest",
      "    steps:",
      "      - uses: actions/checkout@v4",
      "        with:",
      "          ref: ${{ github.event.pull_request.head.sha }}",
    ];
    expect(
      scan({
        ".github/workflows/w.yml": lines(
          "# Reacts to issues: https://github.com/org/repo/issues and pull_request_target docs",
          "on: [push, pull_request]",
          ...body,
        ),
      }, /gha-(?:untrusted-checkout|missing-permissions|checkout-persist|pull-request-target)/),
    ).toEqual([]);
    expect(
      scan({ ".github/workflows/w.yml": lines("on: {issues: {types: [opened]}, push: {}}", ...body) }, /missing-permissions/),
    ).toEqual([".github/workflows/w.yml:1 gha-missing-permissions"]);
  });

  it("does not report an echo of the branch name as a checkout", () => {
    expect(
      scan({
        ".github/workflows/w.yml": lines(
          "on: pull_request_target",
          "permissions: {}",
          "jobs:",
          "  a:",
          "    runs-on: ubuntu-latest",
          "    steps:",
          '      - run: echo "head is ${{ github.event.pull_request.head.sha }}"',
          "      - run: git checkout ${{ github.event.pull_request.head.sha }}",
        ),
      }, /untrusted-checkout/),
    ).toEqual([".github/workflows/w.yml:8 gha-untrusted-checkout"]);
  });

  it("only reports apk --allow-untrusted with an install verb", () => {
    expect(
      scan({
        Dockerfile: lines(
          "FROM alpine:3.20",
          "RUN apk index --allow-untrusted -o APKINDEX.tar.gz *.apk",
          "RUN apk --allow-untrusted add /tmp/x.apk",
          "USER app",
        ),
      }, /unsigned/),
    ).toEqual(["Dockerfile:3 dockerfile-unsigned-packages"]);
  });

  it("rates development default passwords lower than other literals", () => {
    expect(
      scan({
        "compose.yaml": lines(
          "services:",
          "  db:",
          "    environment:",
          "      POSTGRES_PASSWORD: postgres",
          "      - MYSQL_ROOT_PASSWORD=example",
          "      ADMIN_PASSWORD: Xk2v9-QpL7zr",
        ),
      }, /compose-env/),
    ).toEqual([
      "compose.yaml:4 compose-env-dev-secret",
      "compose.yaml:5 compose-env-dev-secret",
      "compose.yaml:6 compose-env-literal-secret",
    ]);
  });

  it("skips input validation and placeholder credentials in Terraform", () => {
    expect(
      scan({
        "v.tf": lines(
          '  condition = !contains(var.members, "allUsers")',
          'secret_key = "EXAMPLE-not-a-key-1234"',
          'password = "placeholder value"',
        ),
      }, /gcp-public|credentials/),
    ).toEqual([]);
  });
});
