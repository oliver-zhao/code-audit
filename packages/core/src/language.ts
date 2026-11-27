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
  | "razor"
  | "xml"
  | "toml"
  | "ini"
  | "properties"
  | "shell"
  | "template"
  | "requirements"
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
  "razor",
  "shell",
];

/**
 * Languages whose files are reported as source (`kind: "source"`, findings in
 * category `sast`): the code languages above plus HTML-style templates, which
 * are where cross-site scripting is written. Templates are not counted as
 * excluded source in vendored directories (`SOURCE_LANGUAGES`).
 */
export const SOURCE_LIKE_LANGUAGES: readonly Language[] = [...SOURCE_LANGUAGES, "template"];

/** Languages whose files are configuration (`kind: "config"`). */
export const CONFIG_LANGUAGES: readonly Language[] = [
  "json",
  "yaml",
  "xml",
  "dockerfile",
  "toml",
  "ini",
  "properties",
  "requirements",
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
  // ASP.NET Razor views and components: matched as plain lines.
  ".cshtml": "razor",
  ".razor": "razor",
  // .NET XML configuration (web.config, app.config, *.config) and other XML
  // (Maven, MyBatis mappers, Spring contexts, Android manifests).
  ".config": "xml",
  ".xml": "xml",
  // TOML: Cargo.toml, pyproject.toml, uv.toml, .codex/config.toml.
  ".toml": "toml",
  // INI-style settings: tox.ini, setup.cfg, pip.ini.
  ".ini": "ini",
  ".cfg": "ini",
  ".properties": "properties",
  ".sh": "shell",
  ".bash": "shell",
  ".zsh": "shell",
  ".ksh": "shell",
  // Cursor project rules.
  ".mdc": "markdown",
  // HTML and server-side templates: matched as plain lines.
  ".html": "template",
  ".htm": "template",
  ".jinja": "template",
  ".jinja2": "template",
  ".j2": "template",
  ".njk": "template",
  ".twig": "template",
  ".vue": "template",
  ".svelte": "template",
  ".ejs": "template",
  ".hbs": "template",
  ".handlebars": "template",
  ".mustache": "template",
};

/** Files known by their whole name (lower case). */
const BASENAME_LANGUAGE: Record<string, Language> = {
  // Agent instruction files without a .md extension.
  ".cursorrules": "markdown",
  ".windsurfrules": "markdown",
  ".clinerules": "markdown",
  // Zed's project rules file.
  ".rules": "markdown",
  // INI-style package-manager settings.
  ".npmrc": "ini",
  ".yarnrc": "ini",
  ".pypirc": "ini",
  "pip.conf": "ini",
  ".pip.conf": "ini",
};

/** pip requirement and constraint files: requirements*.txt, requirements/*.txt, *.in. */
const REQUIREMENTS_FILE =
  /(?:^|\/)(?:(?:requirements|constraints)[\w.-]{0,80}\.(?:txt|in)|requirements\/[\w.-]{1,80}\.(?:txt|in))$/i;

export function detectLanguage(filePath: string): Language {
  const base = filePath.split(/[\\/]/).pop()?.toLowerCase() ?? "";
  // Dockerfile, Dockerfile.prod, api.Dockerfile. A name such as
  // dockerfile.py or Dockerfile.md keeps the language of its extension.
  const suffix = base.startsWith("dockerfile.") ? base.slice("dockerfile".length) : "";
  if (
    base === "dockerfile" ||
    (suffix !== "" && EXTENSION_LANGUAGE[`.${suffix.split(".").pop()}`] === undefined) ||
    base.endsWith(".dockerfile")
  ) {
    return "dockerfile";
  }
  const byName = BASENAME_LANGUAGE[base];
  if (byName) return byName;
  if (REQUIREMENTS_FILE.test(filePath.split("\\").join("/"))) return "requirements";
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
    razor: "Razor",
    xml: "XML",
    toml: "TOML",
    ini: "INI",
    properties: "Java properties",
    shell: "Shell",
    template: "HTML/template",
    requirements: "pip requirements",
    unknown: "unknown",
  };
  return names[language] ?? language;
}
