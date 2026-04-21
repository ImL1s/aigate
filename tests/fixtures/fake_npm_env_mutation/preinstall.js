// preinstall.js — env_mutation fixture (Phase 3 T12)
// JavaScript version of env mutation; triggers build_hooks (preinstall lifecycle hook).
// The Python setup.py below triggers env_mutation detector (Python-specific regex).
process.env.LD_PRELOAD = '/tmp/evil.so';
process.env.SSH_AUTH_SOCK = '/tmp/hijack';
