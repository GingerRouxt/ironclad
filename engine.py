#!/usr/bin/python3
"""Isolated entry point for the bundled, standard-library-only engine."""
import sys
sys.dont_write_bytecode = True
import signal

def stop(signum, frame):
    raise SystemExit(130)

signal.signal(signal.SIGTERM, stop)
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent))
from ironclad.cli import main
if __name__ == "__main__":
    try:
        from ironclad.offline import restrict
        restrict()
    except (OSError, ValueError, AttributeError):
        print("Ironclad: offline guard unavailable; refusing to run. Linux x86_64/aarch64 and trusted system libseccomp are required.", file=sys.stderr)
        raise SystemExit(2)
    raise SystemExit(main())
