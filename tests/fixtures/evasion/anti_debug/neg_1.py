import os
parent = os.getppid()
log(f"running under pid {parent}")
# getppid() read for logging only — no conditional bail-out or evasion logic.
# Detector fires at MEDIUM per Phase 3 rules (parent-sniff alone = MEDIUM).
