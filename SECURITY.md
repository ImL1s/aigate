# Security Policy

## Reporting a Vulnerability

**Do NOT open a public GitHub issue for security vulnerabilities.**

If you discover a security vulnerability in aigate, please report it responsibly:

1. **Email**: Send a detailed report to the maintainers via [GitHub private vulnerability reporting](https://github.com/ImL1s/aigate/security/advisories/new).
2. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will acknowledge your report within **48 hours** and aim to provide a fix or mitigation plan within **7 days**.

## Scope

The following are in scope for security reports:

| Area | Examples |
|------|----------|
| **Pre-filter bypass** | A malicious package that evades all static checks |
| **AI prompt injection** | Crafted package code that manipulates AI model output to return "safe" |
| **Code execution** | Any path where aigate executes package code instead of just reading it |
| **Credential exposure** | API keys, tokens, or sensitive data leaked in logs or output |
| **Dependency vulnerabilities** | Vulnerabilities in aigate's own dependencies |
| **GitHub Action security** | Action input injection, secret leakage, or privilege escalation |

## Out of Scope

- Detection accuracy (false positives / false negatives) -- please use the [false positive template](https://github.com/ImL1s/aigate/issues/new?template=false_positive.yml) instead
- Feature requests
- Issues in third-party AI model behavior (Claude, Gemini, Ollama)

## Supported Versions

| Version | Supported |
|---------|-----------|
| Latest on `main` | Yes |
| PyPI releases | Yes |
| Older releases | Best effort |

## Security Design Principles

aigate is built with these security principles:

1. **Never execute package code** -- the resolver only downloads and extracts source archives
2. **Fail-open by design** -- if aigate crashes, package installation proceeds (safety over availability)
3. **No secrets in config** -- AI backends use CLI tools that manage their own auth
4. **Minimal permissions** -- the GitHub Action only needs read access to the repository

## Acknowledgments

We appreciate the security research community's efforts in keeping the software supply chain safe. Reporters who follow responsible disclosure will be credited in release notes (unless they prefer anonymity).
