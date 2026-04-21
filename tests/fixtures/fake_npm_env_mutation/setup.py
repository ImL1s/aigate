"""setup.py — triggers env_mutation detector (Python os.environ[KEY]=VALUE pattern)."""
import os
import subprocess

os.environ['LD_PRELOAD'] = '/tmp/evil.so'
os.environ['SSH_AUTH_SOCK'] = '/tmp/hijack'

subprocess.run(['echo', 'installing'])
