/**
 * Cleanup of external-tool runs on SIGINT, SIGTERM, SIGHUP and process exit.
 *
 * A run registers the temporary paths it writes (a report, a repository
 * copy) and the child processes it starts. While at least one run is
 * registered, handlers kill those children - their whole process group when
 * they were started detached - and remove the paths synchronously; a signal
 * handler then re-raises the signal when no other listener is left, so the
 * default action (termination) still happens. The handlers are removed when
 * no run is registered, so a long-lived process (the MCP server) is not
 * affected between scans. A SIGKILL cannot be handled.
 */
import type { ChildProcess } from "node:child_process";
import fs from "node:fs";

interface TrackedChild {
  child: ChildProcess;
  detached: boolean;
}

export interface CleanupHandle {
  /** Pass as `runTool`'s `onSpawn` to have the child killed on a signal. */
  track: (child: ChildProcess) => void;
  /** Kill what is still running, remove the paths and unregister. */
  release: () => void;
}

interface Registration {
  paths: string[];
  children: Set<TrackedChild>;
  detached: boolean;
}

const registrations = new Set<Registration>();
const SIGNALS = ["SIGINT", "SIGTERM", "SIGHUP"] as const;
const handlers = new Map<string, () => void>();

/** Kill a child, and its process group when it leads one. */
export function killProcessTree(child: ChildProcess, detached: boolean): void {
  const pid = child.pid;
  if (pid === undefined) return;
  if (detached && process.platform !== "win32") {
    try {
      process.kill(-pid, "SIGKILL");
      return;
    } catch {
      // the group is gone; fall through to the child itself
    }
  }
  try {
    child.kill("SIGKILL");
  } catch {
    // already gone
  }
}

function cleanSync(registration: Registration): void {
  for (const entry of registration.children) killProcessTree(entry.child, entry.detached);
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
 * Register a run: `paths` are removed and tracked children killed on a
 * signal or exit, and when `release()` is called. `detached` says whether the
 * children are started in their own process group (`runTool`'s `detached`).
 */
export function registerCleanup(paths: string[], options: { detached?: boolean } = {}): CleanupHandle {
  const registration: Registration = {
    paths: [...paths],
    children: new Set(),
    detached: options.detached === true,
  };
  registrations.add(registration);
  install();
  return {
    track: (child) => {
      const entry = { child, detached: registration.detached };
      registration.children.add(entry);
      child.once("close", () => registration.children.delete(entry));
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
