/**
 * Git repositories for the `--history` tests (history.test.ts and
 * realtools.test.ts): synthetic secrets, and a hostile repository whose
 * configuration names a marker program everywhere git could run one.
 */
import fs from "node:fs";
import path from "node:path";
import { spawnSync } from "node:child_process";

/** Obviously synthetic AWS-style key ids, built at run time (never in the source as one string). */
export const FAKE_KEY_1 = ["AKIA", "QWERTYUIOP", "ZXCVBN"].join("");
export const FAKE_KEY_2 = ["AKIA", "MNBVCXZLKJ", "HGFDSA"].join("");

export const GIT_TEST_ENV = {
  ...process.env,
  GIT_AUTHOR_NAME: "Synthetic Author",
  GIT_AUTHOR_EMAIL: "synthetic-author@example.invalid",
  GIT_COMMITTER_NAME: "Synthetic Author",
  GIT_COMMITTER_EMAIL: "synthetic-author@example.invalid",
  GIT_CONFIG_NOSYSTEM: "1",
  GIT_CONFIG_GLOBAL: "/dev/null",
};

export function git(args: string[], cwd: string): string {
  const result = spawnSync("git", args, { cwd, encoding: "utf8", env: GIT_TEST_ENV });
  if (result.status !== 0) throw new Error(`git ${args.join(" ")} failed: ${result.stderr}`);
  return result.stdout;
}

export function write(repo: string, rel: string, text: string): void {
  const target = path.join(repo, rel);
  fs.mkdirSync(path.dirname(target), { recursive: true });
  fs.writeFileSync(target, text);
}

export function commitAll(repo: string, message: string): string {
  git(["add", "-A"], repo);
  git(["commit", "-qm", message, "--allow-empty"], repo);
  return git(["rev-parse", "HEAD"], repo).trim();
}

export function newRepo(temp: string, name: string): string {
  const repo = path.join(temp, name);
  fs.mkdirSync(repo, { recursive: true });
  git(["init", "-q", "-b", "main"], repo);
  return repo;
}

/** A program that creates `marker` when it is run, whatever its arguments. */
export function markerProgram(temp: string, name: string): { program: string; marker: string } {
  const marker = path.join(temp, `${name}.marker`);
  const program = path.join(temp, `${name}.sh`);
  fs.writeFileSync(program, `#!/bin/sh\n: > ${JSON.stringify(marker)}\ncat 2>/dev/null\nexit 0\n`, "utf8");
  fs.chmodSync(program, 0o755);
  return { program, marker };
}

/**
 * A repository whose configuration names a marker program in every place git
 * could run one, and which hides a ref holding a secret from fetches.
 */
export function makeHostileRepository(temp: string, name: string): {
  repo: string;
  marker: string;
  program: string;
  hiddenCommit: string;
} {
  const repo = newRepo(temp, name);
  const { program, marker } = markerProgram(temp, name);
  write(repo, "a.py", "print('a')\n");
  write(repo, "b.txt", "plain\n");
  write(repo, ".gitattributes", "* filter=evil diff=evil\n*.py diff=evil\n");
  commitAll(repo, "init");
  write(repo, "a.py", "print('changed')\n");
  commitAll(repo, "change");
  // A commit reachable only from a ref that upload-pack is told to hide.
  git(["checkout", "-q", "-b", "side"], repo);
  write(repo, "side.py", `aws_key = "${FAKE_KEY_2}"\n`);
  const hiddenCommit = commitAll(repo, "side");
  git(["checkout", "-q", "main"], repo);
  git(["update-ref", "refs/hidden/side", hiddenCommit], repo);
  git(["branch", "-q", "-D", "side"], repo);
  const hooks = path.join(repo, "evil-hooks");
  fs.mkdirSync(hooks);
  for (const hook of [
    "post-checkout",
    "reference-transaction",
    "pre-auto-gc",
    "post-index-change",
    "fsmonitor-watchman",
    "pre-upload-pack",
  ]) {
    fs.copyFileSync(program, path.join(hooks, hook));
    fs.chmodSync(path.join(hooks, hook), 0o755);
    fs.copyFileSync(program, path.join(repo, ".git", "hooks", hook));
    fs.chmodSync(path.join(repo, ".git", "hooks", hook), 0o755);
  }
  const config: Array<[string, string]> = [
    ["core.fsmonitor", program],
    ["core.hooksPath", hooks],
    ["core.pager", program],
    ["core.sshCommand", program],
    ["core.alternateRefsCommand", program],
    ["filter.evil.clean", program],
    ["filter.evil.smudge", program],
    ["filter.evil.process", program],
    ["filter.evil.required", "true"],
    ["diff.evil.textconv", program],
    ["diff.evil.command", program],
    ["diff.external", program],
    ["uploadpack.packObjectsHook", program],
    ["uploadpack.hideRefs", "refs/hidden"],
    ["transfer.hideRefs", "refs/hidden"],
    ["gpg.program", program],
    ["log.showSignature", "true"],
    ["credential.helper", `!${program}`],
    ["alias.log", `!${program}`],
    ["alias.clone", `!${program}`],
    ["alias.rev-list", `!${program}`],
    ["alias.cat-file", `!${program}`],
  ];
  for (const [key, value] of config) git(["config", key, value], repo);
  write(repo, ".git/info/attributes", "* filter=evil diff=evil\n");
  fs.rmSync(marker, { force: true });
  return { repo, marker, program, hiddenCommit };
}
