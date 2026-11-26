import path from "node:path";
import { fileURLToPath } from "node:url";

// Keep the unit tests hermetic. When the real scanners are on PATH (for
// example `.tools/bin` during M2.1 verification) the fake-executable tests must
// not accidentally discover and run them. The dedicated real-tool test file
// adds `.tools/bin` back explicitly.
const here = path.dirname(fileURLToPath(import.meta.url));
const toolsBin = path.resolve(here, "../../../.tools/bin");
const current = process.env.PATH ?? "";
const kept = current
  .split(path.delimiter)
  .filter((entry) => entry.length > 0 && path.resolve(entry) !== toolsBin);
process.env.PATH = kept.join(path.delimiter);