/**
 * Hard wall-clock limits for synchronous work.
 *
 * A JavaScript regular expression that backtracks exponentially does not
 * return, and nothing running on the same thread can stop it: a deadline that
 * is checked between two matches is never reached. `node:vm` can - a script
 * run with `timeout` is terminated by a watchdog thread, and the termination
 * also stops the functions that script called, whichever realm they were
 * created in, including a regular expression in the middle of a match.
 *
 * `runInterruptible(fn, ms)` runs `fn` that way. Rules for `fn`:
 *
 * - only computation (pattern matching over strings already in memory). A
 *   termination skips `catch` and `finally` blocks, so `fn` must not hold a
 *   file descriptor or a lock;
 * - state it has written before the interruption is kept as it is, so it
 *   should only append to collections.
 *
 * The cost is about 40 microseconds per call: wrap a file, not a line.
 */
import vm from "node:vm";

export class InterruptedError extends Error {
  readonly code = "INTERRUPTED";

  constructor(readonly timeoutMs: number) {
    super(`execution interrupted after ${timeoutMs} ms`);
    this.name = "InterruptedError";
  }
}

const sandbox: { f?: () => unknown } = Object.create(null) as { f?: () => unknown };
const context = vm.createContext(sandbox, {
  name: "code-audit-interruptible",
  codeGeneration: { strings: false, wasm: false },
});
const script = new vm.Script("f()", { filename: "code-audit-interruptible.js" });

/**
 * Run `fn` and return its result; throw `InterruptedError` when it has not
 * returned after `timeoutMs` milliseconds of wall-clock time. Errors thrown by
 * `fn` pass through unchanged. Calls may be nested.
 */
export function runInterruptible<T>(fn: () => T, timeoutMs: number): T {
  const ms = Math.max(1, Math.ceil(timeoutMs));
  const previous = sandbox.f;
  sandbox.f = fn;
  try {
    return script.runInContext(context, { timeout: ms }) as T;
  } catch (error) {
    if (
      typeof error === "object" &&
      error !== null &&
      (error as { code?: unknown }).code === "ERR_SCRIPT_EXECUTION_TIMEOUT"
    ) {
      throw new InterruptedError(ms);
    }
    throw error;
  } finally {
    sandbox.f = previous;
  }
}
