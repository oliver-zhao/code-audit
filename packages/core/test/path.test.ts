import path from "node:path";
import fs from "node:fs";
import os from "node:os";
import { afterAll, describe, expect, it } from "vitest";
import { resolveInside, validateAuditRoot } from "../src/pathJail.js";
import { cleanup, makeTempDir, writeFile } from "./helpers.js";

const root = makeTempDir("jail-root");
const outside = makeTempDir("jail-outside");
writeFile(root, "inside.txt", "inside");
writeFile(outside, "secret.txt", "outside");

afterAll(() => {
  cleanup(root);
  cleanup(outside);
});

describe("path jail", () => {
  it("resolves files inside the root", () => {
    const resolved = resolveInside(root, "inside.txt");
    expect(resolved).toBe(fs.realpathSync(path.join(root, "inside.txt")));
  });

  it("rejects ../ traversal", () => {
    const target = `../${path.basename(outside)}/secret.txt`;
    expect(() => resolveInside(root, target)).toThrow(/escapes the audit root/);
  });

  it("rejects absolute paths outside the root", () => {
    expect(() =>
      resolveInside(root, path.join(outside, "secret.txt")),
    ).toThrow(/escapes the audit root/);
  });

  it("rejects symlinks that escape the root", () => {
    fs.symlinkSync(outside, path.join(root, "escape-dir"));
    expect(() => resolveInside(root, "escape-dir/secret.txt")).toThrow(
      /escapes the audit root/,
    );
    fs.symlinkSync(
      path.join(outside, "secret.txt"),
      path.join(root, "escape-file.txt"),
    );
    expect(() => resolveInside(root, "escape-file.txt")).toThrow(
      /escapes the audit root/,
    );
  });

  it("refuses / and the home directory as audit roots", () => {
    expect(() => validateAuditRoot("/")).toThrow(/filesystem root/);
    expect(() => validateAuditRoot(os.homedir())).toThrow(/home directory/);
  });

  it("allows the root itself and non-existent paths below it", () => {
    expect(resolveInside(root, ".")).toBe(fs.realpathSync(root));
    expect(resolveInside(root, "not-created-yet/report.md")).toContain(
      path.join(fs.realpathSync(root), "not-created-yet"),
    );
  });
});

/**
 * Cross-platform regression tests. On macOS the OS temp directory lives below
 * a symlink (/var -> /private/var, /tmp -> /private/tmp), so an audit root is
 * routinely reached through a symlinked parent. These tests build their own
 * symlinked layout so they exercise the same situation on every OS:
 *
 *   base/real/project        the real audit root
 *   base/real/outside        a directory outside the root
 *   base/alias    -> real    symlinked PARENT of the root
 *   base/rootlink -> real/project   the root itself is a symlink
 */
describe("path jail with symlinked roots", () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "code-audit-jail-"));
  const realProject = path.join(base, "real", "project");
  const realOutside = path.join(base, "real", "outside");
  writeFile(realProject, "src/inside.txt", "inside");
  writeFile(realOutside, "secret.txt", "outside");
  // A sibling whose name has the root as a string prefix.
  writeFile(`${realProject}-sibling`, "secret.txt", "outside");
  fs.symlinkSync(path.join(base, "real"), path.join(base, "alias"), "dir");
  fs.symlinkSync(realProject, path.join(base, "rootlink"), "dir");
  // Hostile content inside the repository.
  fs.symlinkSync(realOutside, path.join(realProject, "escape-dir"), "dir");
  fs.symlinkSync(
    path.join(realOutside, "secret.txt"),
    path.join(realProject, "escape-file.txt"),
    "file",
  );
  fs.symlinkSync(
    path.join(base, "alias", "outside"),
    path.join(realProject, "escape-via-alias"),
    "dir",
  );
  fs.symlinkSync(
    path.join(realProject, "missing-target"),
    path.join(realProject, "dangling"),
  );
  fs.symlinkSync(path.join(base, "nowhere"), path.join(base, "dangling-root"));

  const canonicalRoot = fs.realpathSync.native(realProject);
  const viaParent = path.join(base, "alias", "project");
  const viaLink = path.join(base, "rootlink");

  afterAll(() => cleanup(base));

  it.each([
    ["a symlinked parent directory", viaParent],
    ["a root that is itself a symlink", viaLink],
    ["the non-canonical OS temp path", realProject],
  ])("accepts a root reached through %s", (_label, root) => {
    expect(validateAuditRoot(root).root).toBe(canonicalRoot);
    expect(resolveInside(root, "src/inside.txt")).toBe(
      path.join(canonicalRoot, "src", "inside.txt"),
    );
    expect(resolveInside(root, ".")).toBe(canonicalRoot);
    expect(resolveInside(root, "new-dir/report.md")).toBe(
      path.join(canonicalRoot, "new-dir", "report.md"),
    );
    // Absolute spellings of an inside file are accepted whichever alias of the
    // root they use; they all canonicalize to the same real path.
    for (const alias of [viaParent, viaLink, realProject, canonicalRoot]) {
      expect(resolveInside(root, path.join(alias, "src", "inside.txt"))).toBe(
        path.join(canonicalRoot, "src", "inside.txt"),
      );
    }
  });

  it.each([
    ["a symlinked parent directory", viaParent],
    ["a root that is itself a symlink", viaLink],
    ["the canonical root", canonicalRoot],
  ])("still rejects every escape when the root is %s", (_label, root) => {
    const escapes = [
      // Symlinks inside the root that point outside.
      "escape-dir/secret.txt",
      "escape-dir",
      "escape-file.txt",
      "escape-via-alias/secret.txt",
      "escape-dir/not-created-yet.txt",
      // `..` traversal.
      "../outside/secret.txt",
      "src/../../outside/secret.txt",
      "..",
      // Sibling directory sharing the root's name as a prefix.
      "../project-sibling/secret.txt",
      // Absolute paths, canonical and through every alias.
      path.join(realOutside, "secret.txt"),
      path.join(fs.realpathSync.native(realOutside), "secret.txt"),
      path.join(base, "alias", "outside", "secret.txt"),
      path.join(`${realProject}-sibling`, "secret.txt"),
      path.join(viaLink, "..", "outside", "secret.txt"),
    ];
    for (const target of escapes) {
      expect(() => resolveInside(root, target), target).toThrow(
        /escapes the audit root/,
      );
    }
    // `..` after a symlinked directory is resolved lexically, never through
    // the link target, so this names a file inside the root.
    expect(resolveInside(root, "escape-dir/../src/inside.txt")).toBe(
      path.join(canonicalRoot, "src", "inside.txt"),
    );
  });

  it("refuses dangling symlinks inside the root and as the root", () => {
    expect(() => resolveInside(viaParent, "dangling")).toThrow(
      /broken or out-of-root symbolic link/,
    );
    expect(() => resolveInside(viaParent, "dangling/child.txt")).toThrow(
      /broken or out-of-root symbolic link/,
    );
    expect(() => validateAuditRoot(path.join(base, "dangling-root"))).toThrow(
      /does not exist/,
    );
  });

  it("refuses a file and a symlink to a file as the audit root", () => {
    expect(() =>
      validateAuditRoot(path.join(realProject, "src", "inside.txt")),
    ).toThrow(/not a directory/);
    expect(() =>
      validateAuditRoot(path.join(realProject, "escape-file.txt")),
    ).toThrow(/not a directory/);
  });

  it("refuses symlinks to / and to the home directory as audit roots", () => {
    const toFsRoot = path.join(base, "to-fs-root");
    const toHome = path.join(base, "to-home");
    fs.symlinkSync(path.parse(base).root, toFsRoot, "dir");
    fs.symlinkSync(os.homedir(), toHome, "dir");
    expect(() => validateAuditRoot(toFsRoot)).toThrow(/filesystem root/);
    expect(() => validateAuditRoot(toHome)).toThrow(/home directory/);
  });
});

/** Swap the case of every ASCII letter. */
function swapCase(value: string): string {
  return value.replace(/[a-zA-Z]/g, (ch) =>
    ch === ch.toLowerCase() ? ch.toUpperCase() : ch.toLowerCase(),
  );
}

describe("path jail and filesystem case sensitivity", () => {
  const base = fs.mkdtempSync(path.join(os.tmpdir(), "code-audit-case-"));
  const project = path.join(base, "Project");
  const outside = path.join(base, "Outside");
  writeFile(project, "Src/Inside.txt", "inside");
  writeFile(outside, "Secret.txt", "outside");
  fs.symlinkSync(outside, path.join(project, "Escape-Dir"), "dir");
  const canonicalRoot = fs.realpathSync.native(project);
  // macOS (APFS/HFS+) and Windows default to case-insensitive filesystems.
  const caseInsensitive = fs.existsSync(path.join(base, "pROJECT"));

  afterAll(() => cleanup(base));

  it.runIf(caseInsensitive)(
    "canonicalizes a differently-cased root and paths below it",
    () => {
      const shouted = path.join(base, "PROJECT");
      expect(validateAuditRoot(shouted).root).toBe(canonicalRoot);
      expect(resolveInside(shouted, "SRC/INSIDE.TXT")).toBe(
        path.join(canonicalRoot, "Src", "Inside.txt"),
      );
      // An absolute, differently-cased spelling of an inside file is the same
      // file and is accepted, with the canonical spelling returned.
      expect(
        resolveInside(project, path.join(base, "project", "src", "inside.txt")),
      ).toBe(path.join(canonicalRoot, "Src", "Inside.txt"));
    },
  );

  it.runIf(caseInsensitive)(
    "does not let a case variation bypass the jail",
    () => {
      for (const root of [project, path.join(base, "PROJECT")]) {
        for (const target of [
          "ESCAPE-DIR/Secret.txt",
          "escape-dir/SECRET.TXT",
          "../OUTSIDE/Secret.txt",
          path.join(base, "OUTSIDE", "secret.txt"),
          path.join(swapCase(outside), "Secret.txt"),
        ]) {
          expect(() => resolveInside(root, target), target).toThrow(
            /escapes the audit root/,
          );
        }
      }
    },
  );

  it.runIf(caseInsensitive)(
    "refuses the home directory under a differently-cased spelling",
    () => {
      const home = os.homedir();
      const variant = path.join(
        path.dirname(home),
        swapCase(path.basename(home)),
      );
      // Only meaningful when the home directory's volume is case-insensitive
      // too and the variant really is the same directory.
      if (variant === home || !fs.existsSync(variant)) return;
      expect(() => validateAuditRoot(variant)).toThrow(/home directory/);
    },
  );

  it.runIf(!caseInsensitive)(
    "treats differently-cased names as different files",
    () => {
      expect(() => validateAuditRoot(path.join(base, "PROJECT"))).toThrow(
        /does not exist/,
      );
      // Names that differ only by case are unrelated entries here, so they
      // resolve (as not-yet-existing paths) inside the root, never through
      // the Escape-Dir symlink.
      expect(resolveInside(project, "ESCAPE-DIR/Secret.txt")).toBe(
        path.join(canonicalRoot, "ESCAPE-DIR", "Secret.txt"),
      );
      expect(() => resolveInside(project, "Escape-Dir/Secret.txt")).toThrow(
        /escapes the audit root/,
      );
    },
  );
});
