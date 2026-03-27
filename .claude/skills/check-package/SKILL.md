---
name: check-package
description: Analyze a package with aigate CLI (static pre-filter + optional AI analysis). Usage: /check-package <name> [version] [ecosystem]
disable-model-invocation: true
---

Analyze the package specified in `$ARGUMENTS` using the aigate CLI.

Parse arguments: first arg is package name, optional second is version, optional third is ecosystem (default: pypi).

```bash
cd /Users/iml1s/Documents/mine/aigate
# Run with AI analysis if backends available, fallback to --skip-ai
.venv/bin/aigate check $ARGUMENTS || .venv/bin/aigate check $ARGUMENTS --skip-ai
```

After analysis, summarize:
1. Verdict and confidence
2. Key risk signals found
3. Recommendation (safe to install, needs review, or block)
