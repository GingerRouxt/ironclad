"""Exact-command allowlist. No shell, PATH lookup, input, or caller-supplied args."""
from dataclasses import dataclass
import os
import pwd
from pathlib import Path
import resource
import signal
import stat
import subprocess
import tempfile
import time

COMMANDS = {
    "schedule_enabled": ("systemctl", "--user", "is-enabled", "zds-ironclad.timer"),
    "schedule_active": ("systemctl", "--user", "is-active", "zds-ironclad.timer"),
    "units": ("systemctl", "--user", "--failed", "--no-legend", "--no-pager", "--plain"),
    "system_units": ("systemctl", "--failed", "--no-legend", "--no-pager", "--plain"),
    "enabled_units": ("systemctl", "--user", "list-unit-files", "--state=enabled", "--no-legend", "--no-pager"),
    "timers": ("systemctl", "--user", "list-timers", "--all", "--no-legend", "--no-pager"),
    "boot": ("systemd-analyze", "time"),
    "packages": ("pacman", "-Qq"),
    "foreign": ("pacman", "-Qmq"),
    "updates": ("pacman", "-Quq"),
    "user_mise": ("mise", "ls", "--installed", "--global", "--json"),
    "user_uv": ("uv", "tool", "list"),
    "user_flatpak": ("flatpak", "list", "--user", "--app", "--columns=application,version"),
    "sockets": ("ss", "-H", "-lntu"),
    "disks": ("lsblk", "-J", "-o", "TYPE,FSTYPE"),
    "gpu": ("lspci", "-mm"),
    "power": ("powerprofilesctl", "get"),
    "clock": ("timedatectl", "show", "--property=NTPSynchronized", "--value"),
}


@dataclass
class Result:
    state: str
    output: str = ""
    returncode: int | None = None


def limits():
    resource.setrlimit(resource.RLIMIT_FSIZE, (1048576, 1048576))
    resource.setrlimit(resource.RLIMIT_CPU, (2, 2))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_AS, (268435456, 268435456))


def run(name, timeout=0.6):
    if name not in COMMANDS:
        raise ValueError("command not allowed")
    binary, *args = COMMANDS[name]
    path = Path('/usr/bin') / binary
    try:
        target = path.resolve(strict=True)
        meta = target.stat()
        if not stat.S_ISREG(meta.st_mode) or meta.st_uid != 0 or meta.st_mode & 0o022:
            return Result("unavailable")
    except OSError:
        return Result("unavailable")
    env = {"HOME": pwd.getpwuid(os.getuid()).pw_dir, "PATH": "/usr/bin", "LANG": "C", "LC_ALL": "C", "SYSTEMD_COLORS": "0", "SYSTEMD_PAGER": "cat"}
    runtime = f"/run/user/{os.getuid()}"
    env.update(XDG_RUNTIME_DIR=runtime, DBUS_SESSION_BUS_ADDRESS=f"unix:path={runtime}/bus")
    with tempfile.TemporaryFile() as out, tempfile.TemporaryFile() as err:
        try:
            proc = subprocess.Popen([str(target), *args], stdin=subprocess.DEVNULL, stdout=out,
                                    stderr=err, env=env, start_new_session=True,
                                    preexec_fn=limits, cwd="/")
        except OSError:
            return Result("unavailable")
        deadline = time.monotonic() + timeout
        state = "available"
        try:
            while proc.poll() is None:
                if time.monotonic() > deadline or os.fstat(out.fileno()).st_size >= 1048576 or os.fstat(err.fileno()).st_size >= 1048576:
                    state = "timeout" if time.monotonic() > deadline else "limit"
                    break
                time.sleep(0.01)
        finally:
            # Includes cancellation and descendants of exited leaders.
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait()
        if state != "available":
            return Result(state)
        out.seek(0)
        data = out.read(65537)
        if len(data) > 65536:
            return Result("limit")
        if proc.returncode != 0:
            # pacman returns 1 for empty query sets; callers must distinguish.
            return Result("empty" if binary == "pacman" and proc.returncode == 1 and not data and os.fstat(err.fileno()).st_size == 0 else "unavailable", returncode=proc.returncode)
        return Result("available", data.decode("utf-8", errors="replace"), proc.returncode)
