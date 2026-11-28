/**
 * The checks before `code-audit verdict --role human` records a person's
 * decision. A human decision settles a dispute and locks agents out of the
 * finding, so the CLI makes it a deliberate act at a terminal:
 *
 * - none of the environment variables that coding-agent hosts set in the
 *   shells they run commands in is present (there is no override);
 * - stdin and stdout are both terminals;
 * - the person types the finding id back.
 *
 * This is a speed bump, not a proof: an agent that can drive a pseudo-
 * terminal, or a person who pastes for an agent, gets through. It stops the
 * common case of an agent running the command from its own shell tool.
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

export interface HumanGateInput {
  /** The finding argument as the person gave it (id or fingerprint). */
  finding: string;
  env: Record<string, string | undefined>;
  stdinIsTTY: boolean;
  stdoutIsTTY: boolean;
  /** Shows the prompt. */
  write: (text: string) => void;
  /** Reads one line typed by the person; undefined at end of input. */
  readLine: () => string | undefined;
}

/** Throws `HumanDecisionError` unless a person at a terminal confirmed. */
export function confirmHumanDecision(input: HumanGateInput): void {
  const agent = AGENT_ENVIRONMENT_VARIABLES.filter((name) => input.env[name] !== undefined);
  if (agent.length > 0) {
    throw new HumanDecisionError(
      `--role human is refused in a shell run by a coding agent (${agent.join(", ")} set). ` +
        "A person records this decision in their own terminal; an agent must not",
    );
  }
  if (!input.stdinIsTTY || !input.stdoutIsTTY) {
    throw new HumanDecisionError(
      "--role human needs an interactive terminal (stdin and stdout): the decision is confirmed by typing the finding id",
    );
  }
  input.write(
    `You are recording a person's decision on ${input.finding}. It settles any dispute between reviewers, and agents can no longer change it.\n` +
      `Type ${input.finding} to confirm: `,
  );
  const typed = input.readLine();
  if (typed === undefined || typed.trim() !== input.finding) {
    throw new HumanDecisionError("the finding id was not typed back; nothing was recorded");
  }
}

/** One line from the terminal, read synchronously from file descriptor 0. */
export function readTerminalLine(): string | undefined {
  const bytes: number[] = [];
  const buffer = Buffer.alloc(1);
  for (;;) {
    let read: number;
    try {
      read = fs.readSync(0, buffer, 0, 1, null);
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === "EAGAIN") continue;
      return undefined;
    }
    if (read === 0) return bytes.length > 0 ? Buffer.from(bytes).toString("utf8") : undefined;
    if (buffer[0] === 10) return Buffer.from(bytes).toString("utf8").replace(/\r$/, "");
    bytes.push(buffer[0] as number);
    if (bytes.length > 1000) return undefined;
  }
}
