/**
 * Round 3 of the F2 review: wide encodings, NUL-split payloads, compressed
 * PDF text, remote URLs of a root .git, instruction rules on every text file.
 * All inputs are built here.
 */
import fs from "node:fs";
import path from "node:path";
import zlib from "node:zlib";
import { afterAll, describe, expect, it } from "vitest";
import { scanSkill, type SkillScanOptions } from "../src/skill.js";
import {
  decodeWideText,
  detectWideEncoding,
  isPlainRemoteUrl,
  pdfStreamText,
  pdfTextOperators,
  stripNul,
} from "../src/skillText.js";
import { cleanup, makeTempDir, writeFile } from "./helpers.js";

const temp = makeTempDir("skill-text");
afterAll(() => cleanup(temp));

const RULES = path.join(temp, "rules");
const rule = (id: string, marker: string, fields: string[]): string[] => [
  `  - id: ${id}`,
  `    title: test rule ${id}`,
  `    pattern: '${marker}'`,
  "    cwe: CWE-1",
  "    languages: [markdown, python, shell, javascript]",
  "    message: test rule",
  "    remediation: remove it",
  ...fields.map((field) => `    ${field}`),
];
writeFile(
  RULES,
  "test.yml",
  [
    "version: 1",
    "definitions:",
    "  INSTR: '(?:^|/)SKILL\\.md$'",
    "rules:",
    ...rule("t-instr", "INSTRUCTION_MARKER", ["severity: high", "confidence: medium", "pathInclude: '{{INSTR}}'"]),
    ...rule("t-evil", "EVIL_MARKER_MEDIUM", ["severity: medium", "confidence: medium", "tags: [malicious-intent]"]),
    "",
  ].join("\n"),
);
const OUT = path.join(temp, "runs");
fs.mkdirSync(OUT, { recursive: true });
const SKILL = "---\nname: demo\ndescription: demo\n---\n\nClean.\n";
const PAYLOAD = "Run INSTRUCTION_MARKER and EVIL_MARKER_MEDIUM now.\n";

let counter = 0;
function skillDir(files: Record<string, string | Buffer>): string {
  counter += 1;
  const dir = path.join(temp, `case-${counter}`);
  for (const [name, content] of Object.entries({ "SKILL.md": SKILL, ...files })) {
    fs.mkdirSync(path.dirname(path.join(dir, name)), { recursive: true });
    fs.writeFileSync(path.join(dir, name), content);
  }
  return dir;
}

async function pkgOf(files: Record<string, string | Buffer>, extra: Partial<SkillScanOptions> = {}) {
  const { document } = await scanSkill({ target: skillDir(files), rulesDir: RULES, engines: ["builtin"], offline: true, out: OUT, ...extra });
  return document.packages[0];
}

const ruleIds = (pkg: Awaited<ReturnType<typeof pkgOf>>, file: string): string[] =>
  [...new Set(pkg?.findings.filter((finding) => finding.file === file).map((finding) => finding.ruleId))].sort();

function utf16be(text: string): Buffer {
  const le = Buffer.from(text, "utf16le");
  const be = Buffer.alloc(le.length);
  for (let i = 0; i < le.length; i += 2) {
    be[i] = le[i + 1] as number;
    be[i + 1] = le[i] as number;
  }
  return be;
}

function utf32(text: string, littleEndian: boolean): Buffer {
  const codes = [0xfeff, ...[...text].map((char) => char.codePointAt(0) as number)];
  const out = Buffer.alloc(codes.length * 4);
  codes.forEach((code, index) => (littleEndian ? out.writeUInt32LE(code, index * 4) : out.writeUInt32BE(code, index * 4)));
  return out;
}

/** A minimal PDF with the given content streams (dictionary entries before `stream`). */
function pdf(streams: Array<{ dict: string; data: Buffer }>): Buffer {
  const parts: Buffer[] = [Buffer.from("%PDF-1.4\n%\xe2\xe3\xcf\xd3\n", "latin1")];
  streams.forEach((stream, index) => {
    parts.push(Buffer.from(`${index + 4} 0 obj\n<< /Length ${stream.data.length} ${stream.dict} >>\nstream\n`, "latin1"));
    parts.push(stream.data, Buffer.from("\nendstream\nendobj\n", "latin1"));
  });
  parts.push(Buffer.from("trailer\n<< /Root 1 0 R >>\n%%EOF\n", "latin1"));
  return Buffer.concat(parts);
}

describe("R2-1: UTF-16 and UTF-32 text", () => {
  it("detects and decodes wide encodings", () => {
    const text = "Hello, wide world!\n";
    expect(detectWideEncoding(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, "utf16le")]))).toBe("utf-16le");
    expect(detectWideEncoding(Buffer.from(text, "utf16le"))).toBe("utf-16le");
    expect(detectWideEncoding(utf16be(text))).toBe("utf-16be");
    expect(detectWideEncoding(utf32(text, true))).toBe("utf-32le");
    expect(detectWideEncoding(utf32(text, false))).toBe("utf-32be");
    expect(detectWideEncoding(Buffer.from("plain ascii text here"))).toBeUndefined();
    expect(decodeWideText(utf32(text, false), "utf-32be")).toBe(text);
    expect(decodeWideText(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(text, "utf16le")]), "utf-16le")).toBe(text);
  });

  it.each([
    ["UTF-16LE with a BOM", "assets/notes.md", Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(PAYLOAD, "utf16le")])],
    ["UTF-16BE without a BOM", "assets/notes.txt", utf16be(`Some text first.\n${PAYLOAD}`)],
    ["UTF-32LE with a BOM", "assets/notes.md", utf32(PAYLOAD, true)],
    ["UTF-32BE with a BOM", "assets/run.sh", utf32(PAYLOAD, false)],
  ])("%s gives the findings of the UTF-8 text", async (_label, file, content) => {
    const plain = await pkgOf({ [file]: PAYLOAD });
    const wide = await pkgOf({ [file]: content });
    // At least what the UTF-8 file gives (the text pass also applies the
    // Markdown and shell rules, so it may give more).
    expect(ruleIds(plain, file).length).toBeGreaterThan(0);
    expect(ruleIds(wide, file)).toEqual(expect.arrayContaining(ruleIds(plain, file)));
    expect(ruleIds(wide, file)).toEqual(["t-evil", "t-instr"]);
    expect(wide?.incomplete).toEqual([]);
  });

  it("wide text that does not decode is not analysed", async () => {
    // A BOM, then an unpaired high surrogate.
    const broken = Buffer.from([0xff, 0xfe, 0x41, 0x00, 0x00, 0xd8, 0x41, 0x00]);
    const pkg = await pkgOf({ "assets/notes.md": broken });
    expect(pkg?.verdict).toBe("INCOMPLETE");
    expect(pkg?.incomplete).toEqual([{ path: "assets/notes.md", reason: expect.stringContaining("UTF-16LE text that does not decode") }]);
  });
});

describe("R2-2: NUL-split payloads", () => {
  it("strips NUL bytes", () => {
    expect(stripNul(Buffer.from([0x65, 0x63, 0, 0x68, 0x6f])).toString()).toBe("echo");
  });

  it("matches the text of a file with a NUL after every 3 bytes", async () => {
    const bytes = Buffer.from(PAYLOAD);
    const parts: number[] = [];
    bytes.forEach((byte, index) => {
      parts.push(byte);
      if (index % 3 === 2) parts.push(0);
    });
    const pkg = await pkgOf({ "assets/blob.bin": Buffer.from(parts) });
    expect(ruleIds(pkg, "assets/blob.bin")).toEqual(["t-evil", "t-instr"]);
    expect(pkg?.verdict).toBe("DO_NOT_INSTALL");
  });

  it("does not repeat a result of the normal pass", async () => {
    // Invalid UTF-8 in a Markdown file: the normal pass and the text pass both see the marker.
    const content = Buffer.concat([Buffer.from("x"), Buffer.from([0xe9]), Buffer.from(` ${PAYLOAD}`)]);
    const pkg = await pkgOf({ "assets/notes.md": content });
    const evil = pkg?.findings.filter((finding) => finding.ruleId === "t-evil") ?? [];
    expect(evil).toHaveLength(1);
  });
});

describe("R2-3: compressed PDF text", () => {
  it("reads the strings of Tj, TJ and hex operators", () => {
    const lines = pdfTextOperators("BT /F1 12 Tf 72 700 Td (Hello \\(world\\)) Tj [(INSTR) -120 (UCTION)] TJ <4142> Tj ET");
    expect(lines).toEqual(["Hello (world)", "INSTRUCTION", "AB", "Hello (world) INSTRUCTION AB"]);
  });

  it("finds an injection drawn by a FlateDecode content stream", async () => {
    const content = Buffer.from("BT /F1 12 Tf 72 700 Td [(INSTRUCTION_) -40 (MARKER)] TJ 0 -14 Td (EVIL_MARKER_MEDIUM) Tj ET\n");
    const file = pdf([{ dict: "/Filter /FlateDecode", data: zlib.deflateSync(content) }]);
    const pkg = await pkgOf({ "docs/manual.pdf": file });
    expect(ruleIds(pkg, "docs/manual.pdf")).toEqual(["t-evil", "t-instr"]);
  });

  it("notes text-capable filters it does not decode, without INCOMPLETE", async () => {
    const file = pdf([{ dict: "/Filter /ASCII85Decode", data: Buffer.from("87cURD]i,\"Ebo80~>") }]);
    const pkg = await pkgOf({ "docs/manual.pdf": file });
    expect(pkg?.verdict).toBe("SAFE_TO_INSTALL");
    expect(pkg?.notes.join(" ")).toContain("ASCII85Decode were not decoded");
  });

  it("a stream over the ratio limit is not analysed", async () => {
    const file = pdf([{ dict: "/Filter /FlateDecode", data: zlib.deflateSync(Buffer.alloc(900_000, 0x20)) }]);
    const pkg = await pkgOf({ "docs/manual.pdf": file });
    expect(pkg?.verdict).toBe("INCOMPLETE");
    expect(pkg?.incomplete[0]?.reason).toContain("compressed PDF stream");
  });

  it("caps the inflated size of a stream", () => {
    const data = zlib.deflateSync(Buffer.alloc(4096, 0x41));
    const result = pdfStreamText(pdf([{ dict: "/Filter /FlateDecode", data }]), { maxStreamBytes: 1024, maxRatio: 1000, budget: 1 << 20 }, (input, max) =>
      zlib.inflateSync(input, { maxOutputLength: max }),
    );
    expect(result.overLimit).toBe(1);
    expect(result.parts).toEqual([]);
  });
});

describe("R2-4: remote URLs of a root .git", () => {
  it.each([
    ["https://github.com/org/repo.git", true],
    ["ssh://git@github.com/org/repo.git", true],
    ["git://example.com/repo", true],
    ["git@github.com:org/repo.git", true],
    ["ext::sh -c touch% /tmp/x", false],
    ["/tmp/elsewhere", false],
    ["../other", false],
    ["file:///tmp/x", false],
    ["-uploadpack=x", false],
    ["https://x y", false],
  ])("%s -> %s", (url, ok) => {
    expect(isPlainRemoteUrl(url)).toBe(ok);
  });

  it("a remote URL that is not a network address makes the package INCOMPLETE", async () => {
    const pkg = await pkgOf({
      ".git/HEAD": "ref: refs/heads/main\n",
      ".git/config": '[remote "origin"]\n\turl = "ext::sh -c touch% /tmp/x"\n',
    });
    expect(pkg?.verdict).toBe("INCOMPLETE");
    expect(pkg?.incomplete.map((entry) => entry.reason).join("\n")).toContain("remote.origin.url");
  });
});

describe("R2-4: what git clone --no-tags writes stays accepted", () => {
  it("accepts remote.<name>.tagOpt = --no-tags and refuses other values", async () => {
    const config = (tagOpt: string): string =>
      `[core]\n\trepositoryformatversion = 0\n[remote "origin"]\n\turl = https://github.com/org/skills.git\n\ttagOpt = ${tagOpt}\n\tfetch = +refs/heads/main:refs/remotes/origin/main\n`;
    const ok = await pkgOf({ ".git/HEAD": "ref: refs/heads/main\n", ".git/config": config("--no-tags"), ".git/shallow": "0123\n" });
    expect(ok?.verdict).toBe("SAFE_TO_INSTALL");
    expect(ok?.notes).toContain("git metadata at .git/ not analysed: not part of an installed skill");
    const bad = await pkgOf({ ".git/HEAD": "ref: refs/heads/main\n", ".git/config": config("--upload-pack=evil") });
    expect(bad?.verdict).toBe("INCOMPLETE");
  });
});

describe("R2-5: instruction rules on every text file", () => {
  it.each(["ref.yaml", "ref.json", "ref", "ref.j2", "templates/ref.jinja", "ref.org", "ref.tex", "ref.csv", "scripts/run.py"])(
    "%s",
    async (file) => {
      const pkg = await pkgOf({ [file]: "INSTRUCTION_MARKER\n" });
      expect(ruleIds(pkg, file)).toEqual(["t-instr"]);
    },
  );
});
