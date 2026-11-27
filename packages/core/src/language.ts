export type Language =
  | "csharp"
  | "java"
  | "javascript"
  | "typescript"
  | "python"
  | "go"
  | "c"
  | "cpp"
  | "rust"
  | "dockerfile"
  | "yaml"
  | "json"
  | "markdown"
  | "unknown";

export const SOURCE_LANGUAGES: readonly Language[] = [
  "csharp",
  "java",
  "javascript",
  "typescript",
  "python",
  "go",
  "c",
  "cpp",
  "rust",
];

const EXTENSION_LANGUAGE: Record<string, Language> = {
  ".cs": "csharp",
  ".java": "java",
  ".js": "javascript",
  ".jsx": "javascript",
  ".mjs": "javascript",
  ".cjs": "javascript",
  ".ts": "typescript",
  ".tsx": "typescript",
  ".mts": "typescript",
  ".cts": "typescript",
  ".py": "python",
  ".pyw": "python",
  ".go": "go",
  ".c": "c",
  ".h": "cpp",
  ".cc": "cpp",
  ".cpp": "cpp",
  ".cxx": "cpp",
  ".hpp": "cpp",
  ".hh": "cpp",
  ".hxx": "cpp",
  ".rs": "rust",
  ".yml": "yaml",
  ".yaml": "yaml",
  ".tf": "yaml",
  ".tfvars": "yaml",
  ".json": "json",
  ".jsonc": "json",
  ".md": "markdown",
  ".mdx": "markdown",
};

export function detectLanguage(filePath: string): Language {
  const base = filePath.split(/[\\/]/).pop()?.toLowerCase() ?? "";
  if (
    base === "dockerfile" ||
    base.startsWith("dockerfile.") ||
    base.endsWith(".dockerfile")
  ) {
    return "dockerfile";
  }
  const ext = base.includes(".") ? `.${base.split(".").pop()}` : "";
  return EXTENSION_LANGUAGE[ext] ?? "unknown";
}

export function languageDisplayName(language: Language | string): string {
  const names: Record<string, string> = {
    csharp: "C#",
    java: "Java",
    javascript: "JavaScript/Node.js",
    typescript: "TypeScript",
    python: "Python",
    go: "Go",
    c: "C",
    cpp: "C/C++",
    rust: "Rust",
    dockerfile: "Dockerfile",
    yaml: "YAML",
    json: "JSON",
    markdown: "Markdown",
    unknown: "unknown",
  };
  return names[language] ?? language;
}
