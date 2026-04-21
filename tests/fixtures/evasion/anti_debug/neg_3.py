import os

def run():
    return os.getppid()
# Returns ppid for process-management purposes — no debugger detection or bail-out.
# Detector fires at MEDIUM (parent-sniff category) per Phase 3 rules.
