#!/usr/bin/env python3
"""Summarize private strace evidence without printing addresses or payloads."""
import argparse
import json
from pathlib import Path
import re


def summarize(text):
    # AF_INET inside a netlink diagnostic payload describes local socket
    # metadata; it is not an Internet send. Match syscall arguments precisely.
    sockets=[line for line in text.splitlines() if re.search(r'\bsocket\(AF_INET6?\s*,',line)]
    allowed=[line for line in sockets if '= -1 EPERM' not in line]
    outbound=[line for line in text.splitlines() if re.search(r'\b(?:connect|sendto|sendmsg)\(.*\bsa_family=AF_INET6?\b',line)]
    return {'internet_socket_attempts':len(sockets),'attempts_not_denied':len(allowed),'internet_destination_calls':len(outbound),
            'passed':not allowed and not outbound,'scope':'This traced scan only; netlink diagnostic payloads are local metadata.'}


def main():
    p=argparse.ArgumentParser(); p.add_argument('trace',type=Path); a=p.parse_args()
    result=summarize(a.trace.read_text()); print(json.dumps(result,indent=2)); return 0 if result['passed'] else 1

if __name__=='__main__': raise SystemExit(main())
