/**
 * Helpers of the skill scan that do not trust file classification:
 *
 * - `extractPrintableText`: the printable text of any file (binary, NUL
 *   bytes, invalid UTF-8), so that rules and secret detectors can run over
 *   it. A polyglot (`%PDF-1.4\necho ...\n\0...` as `manual.pdf`) is an image
 *   to a viewer and a script to `bash`; its text is what matters for an agent.
 * - `gitDirProblems`: whether a `.git` directory looks created by git, so
 *   that the root `.git` of a local checkout may be left out of the scan.
 */
import fs from "node:fs";
import path from "node:path";

export interface ExtractedText {
  /** One extracted run per line. */
  text: string;
  /** One-based line of the original file where each extracted line starts. */
  lines: number[];
}

/** Shortest run of printable characters that is kept when not ended by a newline. */
export const MIN_PRINTABLE_RUN = 4;

/** Length of the UTF-8 sequence starting with `byte`, 0 when it cannot start one. */
function utf8Length(byte: number): number {
  if (byte >= 0xc2 && byte <= 0xdf) return 2;
  if (byte >= 0xe0 && byte <= 0xef) return 3;
  if (byte >= 0xf0 && byte <= 0xf4) return 4;
  return 0;
}

/**
 * Printable runs of `buffer`: ASCII 0x20-0x7E, tab, and well-formed UTF-8
 * sequences. A newline ends a run and the line it belongs to is recorded; a
 * run ended by any other byte (NUL, control, invalid UTF-8) is kept when it
 * has at least `MIN_PRINTABLE_RUN` characters.
 */
export function extractPrintableText(buffer: Uint8Array): ExtractedText {
  const out: string[] = [];
  const lines: number[] = [];
  let line = 1;
  let run = "";
  let runChars = 0;
  let runLine = 1;
  const flush = (force: boolean): void => {
    if (runChars > 0 && (force || runChars >= MIN_PRINTABLE_RUN)) {
      out.push(run);
      lines.push(runLine);
    }
    run = "";
    runChars = 0;
  };
  const decoder = new TextDecoder("utf-8", { fatal: true });
  let index = 0;
  while (index < buffer.length) {
    const byte = buffer[index] as number;
    if (byte === 0x0a) {
      flush(true);
      line += 1;
      index += 1;
      continue;
    }
    if ((byte >= 0x20 && byte <= 0x7e) || byte === 0x09) {
      if (runChars === 0) runLine = line;
      run += String.fromCharCode(byte);
      runChars += 1;
      index += 1;
      continue;
    }
    const length = utf8Length(byte);
    if (length > 0 && index + length <= buffer.length) {
      try {
        const char = decoder.decode(buffer.subarray(index, index + length));
        if (runChars === 0) runLine = line;
        run += char;
        runChars += 1;
        index += length;
        continue;
      } catch {
        // not a well-formed sequence: a separator like any other byte
      }
    }
    flush(false);
    index += 1;
  }
  flush(false);
  return { text: out.join("\n"), lines };
}

const GIT_TOP_LEVEL: Record<string, "file" | "dir"> = {
  HEAD: "file",
  config: "file",
  description: "file",
  hooks: "dir",
  info: "dir",
  objects: "dir",
  refs: "dir",
  logs: "dir",
  index: "file",
  "packed-refs": "file",
  FETCH_HEAD: "file",
  ORIG_HEAD: "file",
  COMMIT_EDITMSG: "file",
  shallow: "file",
};

const CONFIG_KEYS: ReadonlyArray<RegExp> = [
  /^core\.(?:repositoryformatversion|filemode|bare|logallrefupdates|ignorecase|precomposeunicode|symlinks)$/,
  /^remote\..+\.(?:url|fetch)$/,
  /^branch\..+\.(?:remote|merge)$/,
  /^extensions\.objectformat$/,
];

/** Config keys of `text` (`section.sub.key`, lower-cased except the subsection), or a parse problem. */
function configKeys(text: string): { keys: string[]; problem?: string } {
  const keys: string[] = [];
  let section: string | undefined;
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (line === "" || line.startsWith("#") || line.startsWith(";")) continue;
    const header = /^\[\s*([A-Za-z0-9.-]+)(?:\s+"((?:[^"\\]|\\.)*)")?\s*\]$/.exec(line);
    if (header) {
      const name = (header[1] as string).toLowerCase();
      section = header[2] !== undefined ? `${name}.${header[2]}` : name;
      continue;
    }
    const entry = /^([A-Za-z][A-Za-z0-9-]*)\s*(?:=.*)?$/.exec(line);
    if (!entry || section === undefined) return { keys, problem: `unparsed config line ${JSON.stringify(line.slice(0, 80))}` };
    keys.push(`${section}.${(entry[1] as string).toLowerCase()}`);
  }
  return { keys };
}

/**
 * Why a `.git` directory does not look like one git created (empty when it
 * does): only git's standard top-level entries, only `*.sample` hooks, only
 * `info/exclude`, an `objects/` of loose-object and pack files, no symbolic
 * links, and a `config` with no key outside a short allowlist (no fsmonitor,
 * hooksPath, sshCommand, pager, editor, alias, filter, diff or merge driver,
 * credential helper or include).
 */
export function gitDirProblems(gitDir: string): Array<{ path: string; reason: string }> {
  const problems: Array<{ path: string; reason: string }> = [];
  const add = (rel: string, reason: string): void => {
    problems.push({ path: `.git/${rel}`, reason });
  };
  let entries: fs.Dirent[];
  try {
    entries = fs.readdirSync(gitDir, { withFileTypes: true });
  } catch {
    return [{ path: ".git", reason: "git metadata could not be read" }];
  }
  for (const entry of entries) {
    const expected = GIT_TOP_LEVEL[entry.name];
    if (entry.isSymbolicLink()) add(entry.name, "symbolic link inside .git");
    else if (expected === undefined) add(entry.name, "not part of git's standard layout");
    else if (expected === "dir" && !entry.isDirectory()) add(entry.name, "expected a directory");
    else if (expected === "file" && !entry.isFile()) add(entry.name, "expected a file");
  }
  const list = (rel: string): fs.Dirent[] => {
    try {
      return fs.readdirSync(path.join(gitDir, rel), { withFileTypes: true });
    } catch {
      return [];
    }
  };
  for (const hook of list("hooks")) {
    if (!hook.isFile() || !hook.name.endsWith(".sample")) add(`hooks/${hook.name}`, "hook that git does not install (only *.sample hooks are expected)");
  }
  for (const info of list("info")) {
    if (!info.isFile() || info.name !== "exclude") add(`info/${info.name}`, "not part of git's standard layout");
  }
  for (const object of list("objects")) {
    const rel = `objects/${object.name}`;
    if (/^[0-9a-f]{2}$/.test(object.name) && object.isDirectory()) {
      for (const loose of list(rel)) {
        if (!loose.isFile() || !/^[0-9a-f]{38,62}$/.test(loose.name)) add(`${rel}/${loose.name}`, "not a git object");
      }
    } else if (object.name === "pack" && object.isDirectory()) {
      for (const pack of list(rel)) {
        if (!pack.isFile() || !/^pack-[0-9a-f]{40,64}\.(?:pack|idx|rev|keep|promisor|mtimes)$/.test(pack.name)) {
          add(`${rel}/${pack.name}`, "not a git pack file");
        }
      }
    } else if (object.name === "info" && object.isDirectory()) {
      for (const item of list(rel)) {
        if (!item.isFile() || !["packs", "alternates", "commit-graph"].includes(item.name)) add(`${rel}/${item.name}`, "not part of git's standard layout");
        else if (item.name === "alternates") add(`${rel}/${item.name}`, "points git at objects outside the package");
      }
    } else {
      add(rel, "not part of git's standard layout");
    }
  }
  // Links below refs/ and logs/ are refused; their files are ref names.
  const walk = (rel: string, depth: number): void => {
    for (const item of list(rel)) {
      const child = `${rel}/${item.name}`;
      if (item.isSymbolicLink()) add(child, "symbolic link inside .git");
      else if (item.isDirectory() && depth < 20) walk(child, depth + 1);
    }
  };
  walk("refs", 0);
  walk("logs", 0);
  try {
    const stat = fs.lstatSync(path.join(gitDir, "config"));
    if (stat.isFile()) {
      if (stat.size > 64 * 1024) add("config", "config is larger than 64 KiB");
      else {
        const { keys, problem } = configKeys(fs.readFileSync(path.join(gitDir, "config"), "utf8"));
        if (problem) add("config", problem);
        for (const key of keys) {
          if (!CONFIG_KEYS.some((pattern) => pattern.test(key))) add("config", `config key ${key} is not one git writes for a plain clone (it can run commands or change what git does)`);
        }
      }
    }
  } catch {
    // no config file: nothing to check
  }
  return problems;
}
