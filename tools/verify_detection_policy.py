#!/usr/bin/env python3
"""Compile the shipped policy with its pinned Falco binary without processing events."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from ironclad import sensor_policy as policy


def validate(engine):
    engine=Path(engine)
    if hashlib.sha256(engine.read_bytes()).hexdigest()!=policy.ENGINE_SHA:raise ValueError('Falco binary does not match the tested pin')
    with tempfile.TemporaryDirectory(prefix='ironclad-rule-validation-') as temporary:
        folder=Path(temporary);rules=folder/'rules.yaml';rules.write_text(policy.RULES_YAML)
        from ironclad import sensor_package
        plugin=folder/'libkrsi.so';plugin.write_bytes(sensor_package.krsi_payload()['usr/lib/ironclad/libkrsi.so'])
        config=folder/'falco.yaml';config.write_text(policy.CONFIG.replace('/usr/share/ironclad-sensor/rules.yaml',str(rules)).replace(policy.KRSI,str(plugin)))
        result=subprocess.run([str(engine),'-c',str(config),'--dry-run'],stdin=subprocess.DEVNULL,capture_output=True,timeout=30,check=False)
        if result.returncode:raise ValueError('Falco rejected policy: '+result.stderr.decode(errors='replace')[-2000:])
    return {'passed':True,'engine':policy.FALCO_VERSION,'policy':policy.VERSION,'rules':len(policy.RULES),'rules_sha256':hashlib.sha256(policy.RULES_YAML.encode()).hexdigest(),'events_processed':False}


def main():
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--engine',type=Path,default=Path('/usr/lib/ironclad/falco'))
    p.add_argument('--download',action='store_true',help='explicitly fetch and hash-check the pinned official Falco archive for unprivileged CI validation')
    args=p.parse_args()
    if args.download:
        from ironclad import sensor_package
        with tempfile.TemporaryDirectory(prefix='ironclad-ci-policy-') as temporary:
            state=Path(temporary)/'state'
            payload=sensor_package.payload(sensor_package.archive(state,True))
            engine=Path(temporary)/'falco';engine.write_bytes(payload['usr/lib/ironclad/falco']);engine.chmod(0o700)
            print(json.dumps(validate(engine)))
    else:print(json.dumps(validate(args.engine)))
    return 0


if __name__=='__main__':raise SystemExit(main())
