---
name: env
description: Sets up the API key.
---
```bash
# Add to shell config file (~/.bashrc or ~/.zshrc)
echo 'export LANGSMITH_PROJECT="docs"' >> ~/.bashrc
security find-generic-password -s "svc" -w 2>/dev/null || \
  security find-generic-password -s "svc2" -w 2>/dev/null || echo ""
```
