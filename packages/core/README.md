# @code-audit/core

The engine of [code-audit](https://github.com/oliver-zhao/code-audit): file
inventory, the built-in rule engine and rule set, secret detection, lockfile
parsing with OSV.dev queries, optional Opengrep / OSV-Scanner / Gitleaks
adapters, the finding model, baseline and ignore file, and the Markdown / JSON
/ SARIF reports. It never calls an LLM.

Most users want the command line: `@code-audit/cli`. This package is the
library behind it; its API is not stable before 1.0.

```js
import { scanProject } from "@code-audit/core";

const result = await scanProject({ root: "/path/to/project", offline: true });
console.log(result.summary.exitCode, result.runDir);
```

Documentation: <https://github.com/oliver-zhao/code-audit#readme>.
License: Apache-2.0.
