#!/usr/bin/python3
"""Explicit online/interactive companion; never imported by the offline scanner."""
import sys
import signal

def stop(signum, frame):
    raise SystemExit(130)

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGHUP, stop)
from pathlib import Path
sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ironclad.maintenance import main

if __name__ == '__main__':
    raise SystemExit(main())
