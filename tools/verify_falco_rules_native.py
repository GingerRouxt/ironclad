#!/usr/bin/env python3
"""Opt-in destructive acceptance ONLY in a marked disposable KVM/QEMU guest."""
import argparse
import errno
import json
import os
from pathlib import Path
import runpy
import stat
import subprocess
import sys
import tempfile
import time

MARKER = Path('/etc/ironclad-disposable-test')
HELPER = '/usr/lib/ironclad/rule-helper'
TIMER = 'ironclad-rule-updates.timer'
UNIT = 'ironclad-rule-updates.service'
SENSOR = 'ironclad-sensor.service'


def command(args, **kwargs):
    return subprocess.run(args, check=True, capture_output=True, text=True, timeout=300, **kwargs).stdout.strip()


def guard():
    if os.geteuid() != 0 or MARKER.is_symlink():
        raise ValueError('requires root inside an explicitly marked disposable guest')
    meta = MARKER.stat()
    if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022 or MARKER.read_text() != 'ironclad disposable acceptance VM\n':
        raise ValueError('missing or unsafe disposable VM marker')
    if command(['/usr/bin/systemd-detect-virt', '--vm']) not in ('kvm', 'qemu'):
        raise ValueError('refusing to change a non-KVM/QEMU machine')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--confirm-disposable-vm', action='store_true', required=True)
    parser.add_argument('--owner-uid', type=int, default=1000)
    parser.add_argument('--mode', choices=('exercise', 'limits', 'check-boot', 'remove'), default='exercise')
    args = parser.parse_args()
    guard()
    if not 1000 <= args.owner_uid <= 2147483647:
        raise ValueError('invalid guest owner uid')
    env = {'PATH': '/usr/bin', 'LANG': 'C', 'LC_ALL': 'C', 'HOME': '/', 'PKEXEC_UID': str(args.owner_uid)}
    service = runpy.run_path(HELPER)
    base = service['BASE']
    passed = []

    def record(label):
        passed.append(label)
        print('PASS: '+label,file=sys.stderr,flush=True)

    def ctl(*values):
        return command(['/usr/bin/systemctl', *values])

    def pid():
        return ctl('show', SENSOR, '--property=MainPID', '--value')

    def healthy():
        active = service['active']()
        assert active and len(active['catalog']) > 0
        service['health'](time.monotonic_ns(), active['rules_sha256'])
        assert ctl('is-active', SENSOR) == 'active'
        return active

    if args.mode == 'limits':
        with tempfile.TemporaryDirectory(prefix='.limit-fixture-',dir=base) as temp:
            work=Path(temp)/'work';work.mkdir(mode=0o700)
            with service['scratch'](work):
                fs=os.statvfs(work)
                assert fs.f_blocks*fs.f_frsize==32*1024*1024
                try:
                    with (work/'bounded-fixture').open('wb') as output:
                        for _ in range(33):output.write(b'0'*(1024*1024))
                except OSError as error:assert error.errno==errno.ENOSPC
                else:raise AssertionError('scratch exceeded its bound')
            assert not os.path.ismount(work) and not (work/'bounded-fixture').exists()
        record('private-32MiB-scratch-enforces-capacity-and-unmounts')
    elif args.mode == 'check-boot':
        active = healthy()
        assert ctl('is-enabled', TIMER) == 'enabled'
        assert ctl('is-active', TIMER) == 'active'
        assert json.loads(service['read'](base / 'consent.json'))['enabled'] is True
        record('guest-boot-preserves-explicit-consent-and-healthy-rules')
    elif args.mode == 'remove':
        command(['/usr/bin/pacman', '-R', '--noconfirm', 'ironclad-sensor'])
        for unit in (SENSOR, TIMER, UNIT):
            assert ctl('show', unit, '--property=ActiveState', '--value') != 'active'
        assert not Path(HELPER).exists()
        assert base.exists()  # Removal retains evidence; it must not silently delete data.
        record('guest-uninstall-stops-owned-services-removes-helper-retains-state')
    else:
        assert ctl('is-active', SENSOR) == 'active'
        # Reset counters after VM package provisioning; activation health remains strict.
        ctl('reset-failed', SENSOR)
        ctl('restart', SENSOR)
        healthy()
        command([HELPER, 'disable'], env=env)
        original_pid = pid()
        refused = subprocess.run([HELPER, 'update'], env=env, capture_output=True, timeout=10)
        assert refused.returncode != 0 and pid() == original_pid
        record('unconsented-update-refused-without-sensor-restart')
        command([HELPER, 'enable'], env=env)
        assert ctl('is-enabled', TIMER) == 'enabled' and ctl('is-active', TIMER) == 'active'
        # Avoid a concurrent scheduled run during controlled failure fixtures.
        ctl('disable', '--now', TIMER)
        ctl('start', UNIT)
        active = healthy()
        assert json.loads(service['read'](base / 'status.json'))['state'] == 'ok'
        record('actual-systemd-signed-refresh-and-live-sensor-health')
        original_pid = pid()
        ctl('start', UNIT)
        assert pid() == original_pid
        record('unchanged-generation-does-not-restart-sensor')

        # Exercise real download and verification failures in private worker fixtures.
        worker = Path('/usr/lib/ironclad/rule-worker').read_text()
        cases = [
            ('missing-policy', worker.replace("(cache/'indexes/ironclad.yaml').write_text(INDEX)", 'pass'), ('local signature policy unavailable',)),
            ('wrong-workflow', worker.replace('^https://github[.]com/falcosecurity/rules/', '^https://github[.]com/example/other/'), ('identit','subject')),
            ('wrong-issuer', worker.replace('https://token.actions.githubusercontent.com', 'https://invalid.example.test'), ('issuer', 'identit')),
            ('verification-bypass', worker.replace("'--allowed-types','rulesfile'", "'--no-verify','--allowed-types','rulesfile'"), ('signature verification cannot be disabled',)),
            ('invalid-rules', worker.replace("(work/'host-rules.yaml').write_bytes(rules)", "rules += b'\\n- rule: Invalid fixture\\n  desc: fixture\\n  condition: nonexistent.field = true\\n  output: fixture\\n  priority: WARNING\\n'\n    (work/'host-rules.yaml').write_bytes(rules)"), ('nonexistent.field',)),
        ]
        for label, source, reasons in cases:
            with tempfile.TemporaryDirectory(prefix='.acceptance-', dir=base) as temp:
                work = Path(temp) / 'work'
                work.mkdir(mode=0o700)
                (work / 'fixture.py').write_text(source)
                fd = os.open(work, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
                try:
                    invocation = service['sandbox'](work, fd)
                    invocation[-1] = '/work/fixture.py'
                    result = subprocess.run(invocation, env=service['ENV'], pass_fds=(fd,), capture_output=True, text=True, timeout=240)
                    assert result.returncode != 0 and any(reason in (result.stdout + result.stderr).lower() for reason in reasons), label
                    assert not (work / 'result.json').exists(), label
                finally:
                    os.close(fd)
            assert service['active']() == active and pid() == original_pid
            record(label + '-rejected-before-activation')

        # A controlled health-failure injection exercises actual restarts and rollback.
        # This is not represented as a naturally occurring engine crash.
        previous = dict(active, source_sha256='0' * 64)
        service['atomic']('active.json', previous)
        original_health = service['update'].__globals__['health']
        calls = []

        def fail_once(since, digest):
            calls.append(digest)
            if len(calls) == 1:
                raise ValueError('acceptance injected health failure')
            return original_health(since, digest)

        service['update'].__globals__['health'] = fail_once
        try:
            try:
                service['update']()
            except ValueError as error:
                assert str(error) == 'acceptance injected health failure'
            else:
                raise AssertionError('rollback fixture did not fail')
        finally:
            service['update'].__globals__['health'] = original_health
        assert len(calls) == 2 and service['active']() == previous
        assert json.loads(service['read'](base / 'status.json'))['rollback_ok'] is True
        healthy()
        # Controlled rapid restarts must not trip the production crash-loop limit.
        ctl('reset-failed', SENSOR)
        ctl('start', UNIT)
        active = healthy()
        record('injected-health-failure-rolls-back-with-real-service-restarts')
        service['atomic']('pending.json', active)
        service['atomic']('active.json', None)
        ctl('reset-failed', SENSOR)
        service['recover']()
        assert not (base / 'pending.json').exists() and service['active']() == active
        healthy()
        record('pending-transaction-recovery-restores-healthy-generation')
        command([HELPER, 'disable'], env=env)
        assert ctl('show', TIMER, '--property=ActiveState', '--value') != 'active'
        assert service['active']() == active and ctl('is-active', SENSOR) == 'active'
        record('disable-retains-current-rules-and-monitoring')
        # Explicitly opt this disposable guest back in for the separate reboot test.
        command([HELPER, 'enable'], env=env)
    print(json.dumps({'passed': passed, 'environment': 'marked disposable KVM/QEMU guest'}, indent=2))


if __name__ == '__main__':
    main()
