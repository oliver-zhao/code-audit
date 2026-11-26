import { spawn } from "node:child_process";

export interface RunToolOptions {
  cwd?: string;
  timeoutMs?: number;
  maxOutputBytes?: number;
  /** Extra environment variables. Only PATH/HOME/LANG/TMPDIR are forwarded by default. */
  env?: Record<string, string | undefined>;
}

export interface RunToolResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  timedOut: boolean;
  truncated: boolean;
}

const DEFAULT_TIMEOUT_MS = 120_000;
const DEFAULT_MAX_OUTPUT_BYTES = 8 * 1024 * 1024;
const FORWARDED_ENV_KEYS = ["PATH", "HOME", "LANG", "TMPDIR"] as const;

/**
 * Build a minimal environment. Secrets and unrelated variables in the parent
 * environment are intentionally not forwarded to external scanners.
 */
export function minimalEnv(
  extra: Record<string, string | undefined> = {},
): Record<string, string> {
  const env: Record<string, string> = {};
  for (const key of FORWARDED_ENV_KEYS) {
    const value = process.env[key];
    if (typeof value === "string") env[key] = value;
  }
  for (const [key, value] of Object.entries(extra)) {
    if (typeof value === "string") env[key] = value;
  }
  return env;
}

/**
 * Run an external tool with an argument array and `shell: false`.
 *
 * The command is never assembled into a string, so arguments containing spaces
 * or shell metacharacters are passed through verbatim. Output is capped and the
 * process is killed after the timeout.
 */
export function runTool(
  toolPath: string,
  args: string[],
  options: RunToolOptions = {},
): Promise<RunToolResult> {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxOutputBytes = options.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES;

  return new Promise((resolve) => {
    let stdout = "";
    let stderr = "";
    let stdoutBytes = 0;
    let stderrBytes = 0;
    let truncated = false;
    let timedOut = false;
    let settled = false;

    const finish = (exitCode: number): void => {
      if (settled) return;
      settled = true;
      resolve({ exitCode, stdout, stderr, timedOut, truncated });
    };

    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(toolPath, args, {
        cwd: options.cwd,
        shell: false,
        windowsHide: true,
        timeout: timeoutMs,
        env: minimalEnv(options.env),
      });
    } catch (error) {
      resolve({
        exitCode: -1,
        stdout: "",
        stderr: error instanceof Error ? error.message : String(error),
        timedOut: false,
        truncated: false,
      });
      return;
    }

    const append = (
      chunk: Buffer,
      current: string,
      currentBytes: number,
    ): { text: string; bytes: number; truncated: boolean } => {
      if (currentBytes >= maxOutputBytes) {
        return { text: current, bytes: currentBytes, truncated: true };
      }
      const room = maxOutputBytes - currentBytes;
      if (chunk.length > room) {
        return {
          text: current + chunk.subarray(0, room).toString("utf8"),
          bytes: maxOutputBytes,
          truncated: true,
        };
      }
      return {
        text: current + chunk.toString("utf8"),
        bytes: currentBytes + chunk.length,
        truncated: false,
      };
    };

    child.stdout?.on("data", (chunk: Buffer) => {
      const result = append(chunk, stdout, stdoutBytes);
      stdout = result.text;
      stdoutBytes = result.bytes;
      truncated = truncated || result.truncated;
    });
    child.stderr?.on("data", (chunk: Buffer) => {
      const result = append(chunk, stderr, stderrBytes);
      stderr = result.text;
      stderrBytes = result.bytes;
      truncated = truncated || result.truncated;
    });

    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutMs);
    if (typeof timer.unref === "function") timer.unref();

    child.on("error", (error) => {
      clearTimeout(timer);
      if (!settled) {
        stderr += `${stderr ? "\n" : ""}${error instanceof Error ? error.message : String(error)}`;
      }
      finish(-1);
    });
    child.on("close", (code, signal) => {
      clearTimeout(timer);
      if (timedOut) {
        finish(-1);
        return;
      }
      if (typeof code === "number") {
        finish(code);
        return;
      }
      // Killed by a signal without our timeout: report a non-zero exit.
      finish(signal ? -1 : -1);
    });
  });
}