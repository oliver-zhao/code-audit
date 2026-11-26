import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

/** External tools that code-audit can discover on PATH. */
export const EXTERNAL_TOOL_NAMES = [
  "opengrep",
  "semgrep",
  "osv-scanner",
  "gitleaks",
] as const;

export type ExternalToolName = (typeof EXTERNAL_TOOL_NAMES)[number];

export interface ToolInfo {
  name: string;
  path: string;
  /** Version string reported by the tool, when it could be determined. */
  version?: string;
}

export interface FindToolOptions {
  /** Override the PATH used for lookup (defaults to process.env.PATH). */
  pathEnv?: string;
  /** Explicit executable path; when set, PATH is not searched. */
  overridePath?: string;
  /** Timeout for the version probe in milliseconds. */
  timeoutMs?: number;
}

const DEFAULT_VERSION_TIMEOUT_MS = 10_000;
const MAX_VERSION_BYTES = 64 * 1024;

function isExecutableFile(candidate: string): boolean {
  try {
    const stat = fs.statSync(candidate);
    if (!stat.isFile()) return false;
    fs.accessSync(candidate, fs.constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function executableExtensions(): string[] {
  if (process.platform !== "win32") return [""];
  return (process.env.PATHEXT ?? ".EXE;.CMD;.BAT;.COM").split(";");
}

/** Find an executable named `name` on PATH without using a shell. */
export function findExecutable(
  name: string,
  pathEnv = process.env.PATH ?? "",
): string | undefined {
  const extensions = executableExtensions();
  for (const directory of pathEnv.split(path.delimiter)) {
    if (!directory) continue;
    for (const extension of extensions) {
      const candidate = path.join(directory, `${name}${extension}`);
      if (isExecutableFile(candidate)) return candidate;
    }
  }
  return undefined;
}

function versionArguments(name: string): string[] {
  // gitleaks uses a `version` subcommand; the others accept --version.
  return name === "gitleaks" ? ["version"] : ["--version"];
}

/**
 * Run `<tool> --version` and return the first non-empty output line.
 * The process is killed after the timeout and the output is capped, so a
 * misbehaving tool can never hang or flood the caller.
 */
export function probeVersion(
  toolPath: string,
  name: string,
  timeoutMs = DEFAULT_VERSION_TIMEOUT_MS,
): Promise<string | undefined> {
  return new Promise((resolve) => {
    let settled = false;
    let stdout = "";
    let stderr = "";
    let stdoutBytes = 0;
    let stderrBytes = 0;

    const finish = (value: string | undefined): void => {
      if (settled) return;
      settled = true;
      resolve(value);
    };

    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(toolPath, versionArguments(name), {
        shell: false,
        windowsHide: true,
        timeout: timeoutMs,
      });
    } catch {
      finish(undefined);
      return;
    }

    const append = (
      chunk: Buffer,
      current: string,
      currentBytes: number,
    ): { text: string; bytes: number } => {
      if (currentBytes >= MAX_VERSION_BYTES) return { text: current, bytes: currentBytes };
      const room = MAX_VERSION_BYTES - currentBytes;
      const slice = chunk.subarray(0, room);
      return {
        text: current + slice.toString("utf8"),
        bytes: currentBytes + slice.length,
      };
    };

    child.stdout?.on("data", (chunk: Buffer) => {
      const result = append(chunk, stdout, stdoutBytes);
      stdout = result.text;
      stdoutBytes = result.bytes;
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      const result = append(chunk, stderr, stderrBytes);
      stderr = result.text;
      stderrBytes = result.bytes;
    });

    child.on("error", () => finish(undefined));
    child.on("close", () => {
      const text = (stdout || stderr).trim();
      if (!text) {
        finish(undefined);
        return;
      }
      const firstLine = text.split(/\r?\n/)[0]?.trim() ?? "";
      finish(firstLine ? firstLine.slice(0, 200) : undefined);
    });
  });
}

/**
 * Locate a tool and determine its version. Returns undefined when the tool is
 * not present (or the override path is not executable). The version probe is
 * bounded by a timeout and capped output, so a broken tool cannot hang.
 */
export async function findTool(
  name: string,
  options: FindToolOptions = {},
): Promise<ToolInfo | undefined> {
  let toolPath: string | undefined;
  if (options.overridePath !== undefined) {
    toolPath = isExecutableFile(options.overridePath)
      ? path.resolve(options.overridePath)
      : undefined;
  } else {
    toolPath = findExecutable(name, options.pathEnv);
  }
  if (!toolPath) return undefined;
  const version = await probeVersion(toolPath, name, options.timeoutMs);
  return { name, path: toolPath, ...(version ? { version } : {}) };
}

export interface DiscoveredTools {
  opengrep?: ToolInfo;
  semgrep?: ToolInfo;
  "osv-scanner"?: ToolInfo;
  gitleaks?: ToolInfo;
}

/** Discover every supported external tool on PATH (or the given PATH). */
export async function discoverTools(
  options: FindToolOptions = {},
): Promise<DiscoveredTools> {
  const result: DiscoveredTools = {};
  for (const name of EXTERNAL_TOOL_NAMES) {
    const info = await findTool(name, options);
    if (info) result[name] = info;
  }
  return result;
}

export interface SastToolSelection {
  /** The engine name to record in provenance and coverage. */
  engine: "opengrep" | "semgrep";
  info: ToolInfo;
}

/**
 * Pick the SAST engine to use. Opengrep is preferred; Semgrep is used only
 * when Opengrep is not installed.
 */
export async function selectSastTool(
  options: FindToolOptions = {},
): Promise<SastToolSelection | undefined> {
  const opengrep = await findTool("opengrep", options);
  if (opengrep) return { engine: "opengrep", info: opengrep };
  const semgrep = await findTool("semgrep", options);
  if (semgrep) return { engine: "semgrep", info: semgrep };
  return undefined;
}