## Package Security (aigate)

Before installing ANY package via pip, npm, yarn, or pnpm, ALWAYS run:

```
aigate check <package_name>
```

For npm packages:
```
aigate check <package_name> -e npm
```

**Interpret exit codes:**
- Exit 0 = safe, proceed with install
- Exit 1 = suspicious, warn the user before proceeding
- Exit 2 = malicious, DO NOT install. Inform the user immediately.

**For lockfile scanning:**
```
aigate scan requirements.txt
aigate scan package-lock.json
```

This is a supply chain security measure. Never skip this step.
