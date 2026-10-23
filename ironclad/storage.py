"""Owner-only bounded history; no report overwrites or symlink-following writes."""
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import stat
from .model import validate_scan


def open_dir(path, create=False):
    """Walk each component by directory fd; refuse symlinks throughout."""
    path = Path(path).absolute()
    fd = os.open('/', os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in path.parts[1:]:
            if component in ('', '.', '..'):
                raise ValueError('unsafe directory')
            if create:
                try:
                    os.mkdir(component, 0o700, dir_fd=fd)
                except FileExistsError:
                    pass
            newfd = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = newfd
        return fd
    except BaseException:
        os.close(fd)
        raise


def private_dir(path):
    fd = open_dir(path, create=True)
    info = os.fstat(fd)
    if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
        os.close(fd)
        raise ValueError('private directory must be owned by caller with mode 0700')
    return fd


def safe_file(fd, name):
    filefd = os.open(name, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=fd)
    info = os.fstat(filefd)
    if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1 or stat.S_IMODE(info.st_mode) != 0o600:
        os.close(filefd)
        raise ValueError('unsafe private file')
    return filefd


@contextmanager
def scan_lock(runtime=None):
    runtime = Path(runtime or os.environ.get('XDG_RUNTIME_DIR', f'/run/user/{os.getuid()}')) / 'ironclad'
    fd = private_dir(runtime)
    lock = None
    try:
        lock = safe_file(fd, 'scan.lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        if lock is not None:
            os.close(lock)
        os.close(fd)


def export(path, text):
    data = text.encode('utf-8')
    if len(data) > 1048576:
        raise ValueError('report limit')
    path = Path(path).absolute()
    directory = open_dir(path.parent)
    fd = None
    try:
        fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=directory)
        with os.fdopen(fd, 'wb') as stream:
            fd = None
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


class Store:
    def __init__(self, path):
        self.fd = private_dir(path)
        self.db = None
        self.lock = None
        try:
            self.lock = safe_file(self.fd, 'history.lock')
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            for name in ['history.sqlite3', 'history.sqlite3-journal', 'history.sqlite3-wal', 'history.sqlite3-shm']:
                try:
                    meta = os.stat(name, dir_fd=self.fd, follow_symlinks=False)
                except FileNotFoundError:
                    continue
                if not stat.S_ISREG(meta.st_mode) or meta.st_uid != os.getuid() or meta.st_nlink != 1 or meta.st_mode & 0o077:
                    raise ValueError('unsafe database file')
            f = safe_file(self.fd, 'history.sqlite3')
            os.close(f)
            self.db = sqlite3.connect(f'/proc/self/fd/{self.fd}/history.sqlite3', timeout=.2)
            self.db.execute('PRAGMA journal_mode=DELETE')
            self.db.execute('PRAGMA max_page_count=2048')
            version = self.db.execute('PRAGMA user_version').fetchone()[0]
            if version not in (0, 1, 2):
                raise ValueError('unsupported history version')
            self.db.executescript('''CREATE TABLE IF NOT EXISTS scans (id INTEGER PRIMARY KEY, body TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS baseline (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL);
              CREATE TABLE IF NOT EXISTS actions (id INTEGER PRIMARY KEY, previous TEXT, current_hash TEXT NOT NULL, rolled_back INTEGER NOT NULL DEFAULT 0);
              CREATE TABLE IF NOT EXISTS remediation (receipt TEXT PRIMARY KEY, plan TEXT NOT NULL, status TEXT NOT NULL, after_ctime INTEGER, created_at TEXT NOT NULL, finished_at TEXT);
              PRAGMA user_version=2;''')
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.db is not None:
            self.db.close()
            self.db = None
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def __enter__(self): return self
    def __exit__(self, *args): self.close()

    def save(self, scan):
        body = json.dumps(validate_scan(scan), sort_keys=True)
        with self.db:
            self.db.execute('INSERT INTO scans(body) VALUES (?)', (body,))
            self.db.execute('DELETE FROM scans WHERE id NOT IN (SELECT id FROM scans ORDER BY id DESC LIMIT 32)')
        return scan['scan_id']

    def latest(self):
        row = self.db.execute('SELECT body FROM scans ORDER BY id DESC LIMIT 1').fetchone()
        if not row: raise ValueError('no saved scan')
        return validate_scan(json.loads(row[0]))

    def baseline(self):
        row = self.db.execute('SELECT body FROM baseline WHERE id=1').fetchone()
        if not row: raise ValueError('no baseline')
        return validate_scan(json.loads(row[0]))

    def replace_baseline(self, scan):
        body = json.dumps(validate_scan(scan), sort_keys=True)
        previous = self.db.execute('SELECT body FROM baseline WHERE id=1').fetchone()
        digest = hashlib.sha256(body.encode()).hexdigest()
        with self.db:
            self.db.execute('INSERT OR REPLACE INTO baseline VALUES (1, ?)', (body,))
            cursor = self.db.execute('INSERT INTO actions(previous,current_hash) VALUES (?, ?)', (previous[0] if previous else None, digest))
            self.db.execute('DELETE FROM actions WHERE id NOT IN (SELECT id FROM actions ORDER BY id DESC LIMIT 16)')
        return cursor.lastrowid

    def rollback(self, action_id):
        row = self.db.execute('SELECT previous,current_hash,rolled_back FROM actions WHERE id=?', (action_id,)).fetchone()
        current = self.db.execute('SELECT body FROM baseline WHERE id=1').fetchone()
        if not row or row[2] or not current or hashlib.sha256(current[0].encode()).hexdigest() != row[1]:
            raise ValueError('rollback stale or already consumed')
        with self.db:
            if row[0] is None:
                self.db.execute('DELETE FROM baseline')
            else:
                validate_scan(json.loads(row[0]))
                self.db.execute('UPDATE baseline SET body=? WHERE id=1', (row[0],))
            self.db.execute('UPDATE actions SET rolled_back=1 WHERE id=?', (action_id,))


def compare(before, after):
    validate_scan(before); validate_scan(after)
    old = {c['check_id']: c for c in before['checks']}
    new = {c['check_id']: c for c in after['checks']}
    def signature(c):
        return c['status'], c['severity'], c['summary'], [(e['source'], e['value']) for e in c['evidence']]
    return {'new': sorted(new.keys()-old.keys()), 'removed': sorted(old.keys()-new.keys()),
            'changed': sorted(k for k in old.keys() & new.keys() if signature(old[k]) != signature(new[k])),
            'note': 'Removed or unavailable checks do not imply resolved risk; timestamps excluded from comparison.'}
