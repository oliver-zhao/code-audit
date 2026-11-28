/**
 * The checks before a person's decision (`role: "human"`) is recorded. A
 * human decision settles a dispute and locks agents out of the finding, so
 * it must be a deliberate act at a terminal:
 *
 * - none of the environment variables that coding-agent hosts set in the
 *   shells they run commands in is present (there is no override);
 * - stdin and stdout are both terminals;
 * - the person types the finding id back (the CLI asks).
 *
 * `recordVerdict` runs the first two checks itself whenever it is asked to
 * record a human decision, so the exported API is gated like the CLI.
 *
 * This is a speed bump, not a proof: an agent that drives a pseudo-terminal,
 * a host that sets none of these variables, a person who types for an
 * agent, or anyone who can edit the run directory gets through.
 */
import fs from "node:fs";

/**
 * Variables that mark a shell run by a coding agent. Verified locally:
 * CLAUDECODE, CLAUDE_CODE_ENTRYPOINT and AI_AGENT are set in the shells of
 * Claude Code. The others are the names the Codex, OpenCode and DSH hosts
 * are expected to set; those hosts were not installed where this was
 * written, so the names could not be checked (see docs/mcp.md).
 */
export const AGENT_ENVIRONMENT_VARIABLES = [
  "CLAUDECODE",
  "CLAUDE_CODE_ENTRYPOINT",
  "CODEX_SANDBOX",
  "CODEX_SANDBOX_NETWORK_DISABLED",
  "OPENCODE",
  "OPENCODE_BIN_PATH",
  "AI_AGENT",
  "DSH_AGENT",
] as const;

export class HumanDecisionError extends Error {
  readonly code = "HUMAN_DECISION_REFUSED";

  constructor(message: string) {
    super(message);
    this.name = "HumanDecisionError";
  }
}

export interface HumanContext {
  env: Record<string, string | undefined>;
  stdinIsTTY: boolean;
  stdoutIsTTY: boolean;
}

/** The context of this process. */
export function processHumanContext(): HumanContext {
  return {
    env: process.env,
    stdinIsTTY: process.stdin.isTTY === true,
    stdoutIsTTY: process.stdout.isTTY === true,
  };
}

/** Throws `HumanDecisionError` in an agent's shell or without a terminal. */
export function assertHumanContext(context: HumanContext): void {
  const agent = AGENT_ENVIRONMENT_VARIABLES.filter((name) => context.env[name] !== undefined);
  if (agent.length > 0) {
    throw new HumanDecisionError(
      `--role human is refused in a shell run by a coding agent (${agent.join(", ")} set). ` +
        "A person records this decision in their own terminal; an agent must not",
    );
  }
  if (!context.stdinIsTTY || !context.stdoutIsTTY) {
    throw new HumanDecisionError(
      "--role human needs an interactive terminal (stdin and stdout): the decision is confirmed by typing the finding id",
    );
  }
}

export interface HumanGateInput extends HumanContext {
  /** The finding argument as the person gave it (id or fingerprint). */
  finding: string;
  /** Shows the prompt. */
  write: (text: string) => void;
  /** Reads one line typed by the person; undefined at end of input. */
  readLine: () => string | undefined;
}

/** Throws `HumanDecisionError` unless a person at a terminal confirmed. */
export function confirmHumanDecision(input: HumanGateInput): void {
  assertHumanContext(input);
  input.write(
    `You are recording a person's decision on ${input.finding}. It settles any dispute between reviewers, and agents can no longer change it.\n` +
      `Type ${input.finding} to confirm: `,
  );
  const typed = input.readLine();
  if (typed === undefined || typed.trim() !== input.finding) {
    throw new HumanDecisionError("the finding id was not typed back; nothing was recorded");
  }
}

function waitMs(ms: number): void {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
}

/**
 * One line from the terminal, read from file descriptor 0. A blocking read;
 * on a non-blocking stdin (EAGAIN) it waits 20 ms between attempts instead
 * of spinning.
 */
export function readTerminalLine(fd = 0): string | undefined {
  const bytes: number[] = [];
  const buffer = Buffer.alloc(1);
  for (;;) {
    let read: number;
    try {
      read = fs.readSync(fd, buffer, 0, 1, null);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EAGAIN") {
        waitMs(20);
        continue;
      }
      return undefined;
    }
    if (read === 0) return bytes.length > 0 ? Buffer.from(bytes).toString("utf8") : undefined;
    if (buffer[0] === 10) return Buffer.from(bytes).toString("utf8").replace(/\r$/, "");
    bytes.push(buffer[0] as number);
    if (bytes.length > 1000) return undefined;
  }
}
