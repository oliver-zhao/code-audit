import { describe, expect, it } from "vitest";
import { globMatches, globToRegExp } from "../src/glob.js";

describe("glob matcher", () => {
  it("supports `**` matching across path separators", () => {
    expect(globMatches("**", "a/b/c.py")).toBe(true);
    expect(globMatches("a/**", "a/b/c.py")).toBe(true);
    expect(globMatches("a/**", "a/b/c/d.py")).toBe(true);
  });

  it("supports `**/x` matching zero or more leading segments", () => {
    expect(globMatches("**/x.py", "x.py")).toBe(true);
    expect(globMatches("**/x.py", "a/x.py")).toBe(true);
    expect(globMatches("**/x.py", "a/b/x.py")).toBe(true);
    expect(globMatches("**/x.py", "a/b/y.py")).toBe(false);
  });

  it("does not let `*` cross a `/`", () => {
    expect(globMatches("a/*/b.py", "a/x/b.py")).toBe(true);
    expect(globMatches("a/*/b.py", "a/x/y/b.py")).toBe(false);
    expect(globMatches("*.py", "a.py")).toBe(true);
    expect(globMatches("*.py", "dir/a.py")).toBe(false);
  });

  it("supports `?` matching a single non-slash character", () => {
    expect(globMatches("a/?.py", "a/x.py")).toBe(true);
    expect(globMatches("a/?.py", "a/xy.py")).toBe(false);
    expect(globMatches("a/?.py", "a//.py")).toBe(false);
  });

  it("treats regex metacharacters literally", () => {
    expect(globMatches("a+b(1).py", "a+b(1).py")).toBe(true);
    expect(globMatches("a+b(1).py", "aaab1py")).toBe(false);
    expect(globMatches("file[1].txt", "file[1].txt")).toBe(true);
  });

  it("is anchored at both ends", () => {
    expect(globMatches("a.py", "a.py")).toBe(true);
    expect(globMatches("a.py", "xa.py")).toBe(false);
    expect(globMatches("a.py", "a.pyx")).toBe(false);
  });

  it("compiles to an anchored regular expression", () => {
    const re = globToRegExp("src/**/*.ts");
    expect(re.test("src/a.ts")).toBe(true);
    expect(re.test("src/deep/nested/a.ts")).toBe(true);
    expect(re.test("src/a.js")).toBe(false);
  });
});