/**
 * Cleanup of external-tool runs: on SIGINT, SIGTERM, SIGHUP and process exit,
 * on a timeout, and of what an earlier run that was killed left behind.
 *
 * Tools run in code-audit's own process group, so a host that kills that
 * group (an MCP client, a CI runner on cancel, `timeout -s KILL`) takes them
 * down too. To stop one tool without stopping code-audit, the tool and all
 * its descendants are killed by walking the process tree (`ps -A -o
 * pid=,ppid=`): leaves first, then once more for anything started meanwhile.
 *
 * A run registers the temporary paths it writes (a report, a repository
 * copy) and the child processes it starts. While at least one run is
 * registered, handlers kill those trees and remove the paths synchronously; a
 * signal handler then re-raises the signal when no other listener is left, so
 * the default action (termination) still happens. The handlers are removed
 * when no run is registered, so a long-lived process (the MCP server) is not
 * affected between scans. A SIGKILL cannot be handled: `sweepStaleTempEntries`
 * removes what such a run left behind, at the start of a later one.
 */
import { spawnSync, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export interface CleanupHandle {
  /** Pass as `runTool`'s `onSpawn` to have the child killed on a signal. */
  track: (child: ChildProcess) => void;
  /** Kill what is still running, remove the paths and unregister. */
  release: () => void;
}

interface Registration {
  paths: string[];
  children: Set<ChildProcess>;
}

const registrations = new Set<Registration>();
const SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP"] as const;
const handlers = new Map<string, () => void>();

function psExecutable(): string | undefined {
  for (const candidate of ["/bin/ps", "/usr/bin/ps"]) {
    try {
      if (fs.statSync(candidate).isFile()) return candidate;
    } catch {
      // not there
    }
  }
  return undefined;
}

/** `pid -> parent pid` of every process, or undefined when `ps` fails. */
function processTable(): Map<number, number> | undefined {
  const ps = psExecutable();
  if (!ps || process.platform === "win32") return undefined;
  const result = spawnSync(ps, ["-A", "-o", "pid=,ppid="], {
    encoding: "utf8",
    timeout: 5000,
    maxBuffer: 16 * 1024 * 1024,
    env: { PATH: "/usr/bin:/bin", LANG: "C" },
  });
  if (result.status !== 0 || typeof result.stdout !== "string") return undefined;
  const table = new Map<number, number>();
  for (const line of result.stdout.split("\n")) {
    const match = /^\s*(\d+)\s+(\d+)\s*$/.exec(line);
    if (match) table.set(Number(match[1]), Number(match[2]));
  }
  return table;
}

/** Descendants of `root`, deepest first (leaves before their parents). */
export function descendantsOf(root: number, table: Map<number, number>): number[] {
  const children = new Map<number, number[]>();
  for (const [pid, ppid] of table) {
    const list = children.get(ppid);
    if (list) list.push(pid);
    else children.set(ppid, [pid]);
  }
  const order: number[] = [];
  const seen = new Set<number>([root]);
  const queue = [root];
  while (queue.length > 0) {
    const current = queue.shift() as number;
    for (const child of children.get(current) ?? []) {
      if (seen.has(child)) continue;
      seen.add(child);
      order.push(child);
      queue.push(child);
    }
  }
  return order.reverse();
}

function killPid(pid: number): void {
  try {
    process.kill(pid, "SIGKILL");
  } catch {
    // already gone
  }
}

/**
 * Kill a child and all its descendants: a snapshot of the process tree and
 * the descendants killed leaves first, the same once more for descendants
 * started in between, and the child last - while it lives, what it started
 * is still attached to it in the tree.
 */
export function killProcessTree(child: ChildProcess): void {
  const pid = child.pid;
  if (pid === undefined) return;
  if (child.exitCode === null && child.signalCode === null) {
    for (let round = 0; round < 2; round += 1) {
      const table = processTable();
      if (table) for (const descendant of descendantsOf(pid, table)) killPid(descendant);
    }
  }
  try {
    child.kill("SIGKILL");
  } catch {
    // already gone
  }
}

function cleanSync(registration: Registration): void {
  for (const child of registration.children) killProcessTree(child);
  registration.children.clear();
  for (const target of registration.paths) {
    try {
      fs.rmSync(target, { recursive: true, force: true });
    } catch {
      // best effort
    }
  }
}

function cleanAllSync(): void {
  for (const registration of [...registrations]) cleanSync(registration);
  registrations.clear();
  uninstall();
}

function onExit(): void {
  cleanAllSync();
}

function install(): void {
  if (handlers.size > 0) return;
  process.on("exit", onExit);
  for (const signal of SIGNALS) {
    const handler = (): void => {
      cleanAllSync();
      // Without another listener the process would now ignore the signal:
      // raise it again so that the default action happens.
      if (process.listenerCount(signal) === 0) process.kill(process.pid, signal);
    };
    handlers.set(signal, handler);
    process.on(signal, handler);
  }
}

function uninstall(): void {
  process.removeListener("exit", onExit);
  for (const [signal, handler] of handlers) process.removeListener(signal, handler);
  handlers.clear();
}

/**
 * Register a run: `paths` are removed and tracked children (with their
 * descendants) killed on a signal or exit, and when `release()` is called.
 */
export function registerCleanup(paths: string[]): CleanupHandle {
  const registration: Registration = { paths: [...paths], children: new Set() };
  registrations.add(registration);
  install();
  return {
    track: (child) => {
      registration.children.add(child);
      child.once("close", () => registration.children.delete(child));
    },
    release: () => {
      cleanSync(registration);
      registrations.delete(registration);
      if (registrations.size === 0) uninstall();
    },
  };
}

/** Number of registered runs (testing). */
export function activeCleanupCount(): number {
  return registrations.size;
}

/** Names of the temporary entries code-audit creates (and may sweep). */
const SWEPT_DIRECTORY = /^code-audit-(?:history|gitleaks)-[A-Za-z0-9]+$/;
const SWEPT_FILE = /^code-audit-gitleaks-[A-Za-z0-9-]+\.json$/;

/** Entries untouched for longer than this are stale. */
export const STALE_TEMP_AGE_MS = 60 * 60 * 1000;

/**
 * Remove what killed runs left in the temporary directory: entries named
 * exactly like code-audit's own (`code-audit-history-*` and
 * `code-audit-gitleaks-*` directories, `code-audit-gitleaks-*.json` report
 * files of earlier versions), owned by the current user, not modified for
 * more than an hour, and private (mode 0700 for a directory, 0600 for a
 * file). A symbolic link is never followed or removed; nothing else is
 * touched. Returns the number of entries removed.
 */
export function sweepStaleTempEntries(
  options: { dir?: string; now?: number; maxAgeMs?: number } = {},
): number {
  const dir = options.dir ?? os.tmpdir();
  const now = options.now ?? Date.now();
  const maxAgeMs = options.maxAgeMs ?? STALE_TEMP_AGE_MS;
  const uid = typeof process.getuid === "function" ? process.getuid() : undefined;
  if (uid === undefined) return 0;
  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return 0;
  }
  let removed = 0;
  for (const name of names) {
    const isDirName = SWEPT_DIRECTORY.test(name);
    const isFileName = SWEPT_FILE.test(name);
    if (!isDirName && !isFileName) continue;
    const target = path.join(dir, name);
    let stat: fs.Stats;
    try {
      stat = fs.lstatSync(target);
    } catch {
      continue;
    }
    if (stat.isSymbolicLink()) continue;
    if (stat.uid !== uid) continue;
    if (now - stat.mtimeMs <= maxAgeMs) continue;
    const mode = stat.mode & 0o777;
    const eligible =
      (isDirName && stat.isDirectory() && mode === 0o700) ||
      (isFileName && stat.isFile() && mode === 0o600);
    if (!eligible) continue;
    try {
      fs.rmSync(target, { recursive: stat.isDirectory(), force: true });
      removed += 1;
    } catch {
      // best effort
    }
  }
  return removed;
}
