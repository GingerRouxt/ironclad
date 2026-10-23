"""Narrow opt-in remediation. No arbitrary paths/commands or mutating QML IPC."""
from dataclasses import dataclass
import hashlib
import json
import os
from pathlib import Path
import pwd
import secrets
import stat
import time
from uuid import uuid4
from .model import now
from .storage import open_dir

ACTION_ID = 'home.remove_world_write'


@dataclass(frozen=True)
class Plan:
    action_id: str
    uid: int
    device: int
    inode: int
    ctime_ns: int
    before: int
    after: int
    nonce: str
    created: float

    def canonical(self):
        return json.dumps(self.__dict__, sort_keys=True, separators=(',', ':'))

    def digest(self):
        return hashlib.sha256(self.canonical().encode()).hexdigest()

    def public(self):
        return {'action_id': self.action_id, 'target': 'current account home directory',
                'before_mode': f'{self.before:04o}', 'after_mode': f'{self.after:04o}',
                'impact': 'Remove only the other-write permission bit; keep every other mode bit unchanged.',
                'risk': 'May affect intentional shared-home workflows. ACLs and parent permissions are outside this action.',
                'rollback': 'Receipt-based, exact-target restoration; restoring world-write can reduce security.',
                'privileged': False, 'approval': 'Independent interactive terminal; exact plan digest required',
                'expires_in_seconds': 120, 'plan_digest': self.digest()}


def account_home():
    # Never use caller-supplied path, HOME or a filename from a finding.
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def identity(fd):
    meta=os.fstat(fd)
    if meta.st_uid!=os.getuid() or not stat.S_ISDIR(meta.st_mode):
        raise ValueError('owned home directory required')
    return (meta.st_uid, meta.st_dev, meta.st_ino, meta.st_ctime_ns, stat.S_IMODE(meta.st_mode))


def preview(action_id):
    if action_id!=ACTION_ID: raise ValueError('action not allowed')
    fd=open_dir(account_home())
    try:
        uid,dev,ino,ctime,mode=identity(fd)
        if not mode & stat.S_IWOTH: raise ValueError('action not applicable')
        return Plan(action_id,uid,dev,ino,ctime,mode,mode & ~stat.S_IWOTH,secrets.token_hex(16),time.monotonic())
    finally: os.close(fd)


def verify(fd, plan):
    if plan.action_id!=ACTION_ID or plan.after != plan.before & ~stat.S_IWOTH or not plan.before & stat.S_IWOTH:
        raise ValueError('invalid exact action plan')
    if time.monotonic()-plan.created>120 or time.monotonic()<plan.created:
        raise ValueError('plan expired')
    if identity(fd)!=(plan.uid,plan.device,plan.inode,plan.ctime_ns,plan.before):
        raise ValueError('action precondition changed')
    current=open_dir(account_home())
    try:
        if identity(current)!=identity(fd): raise ValueError('home identity changed')
    finally: os.close(current)


def apply(store, plan, approved_digest):
    # This low-level method is never exposed directly to QML. CLI owns TTY consent.
    if not secrets.compare_digest(approved_digest, plan.digest()): raise ValueError('altered action authorization')
    fd=open_dir(account_home())
    receipt=str(uuid4())
    try:
        verify(fd,plan)
        body=plan.canonical()
        with store.db:
            store.db.execute('INSERT INTO remediation VALUES (?, ?, ?, ?, ?, ?)',(receipt,body,'prepared',None,now(),None))
        try:
            os.fchmod(fd,plan.after)
            if identity(fd)[-1]!=plan.after: raise ValueError('action postcondition failed')
            ctime=identity(fd)[3]
            with store.db:
                store.db.execute('UPDATE remediation SET status=?, after_ctime=? WHERE receipt=?',('applied',ctime,receipt))
            return receipt
        except BaseException:
            # Compensate only our exact target/mode. Never overwrite a concurrent change.
            if identity(fd)[-1]==plan.after: os.fchmod(fd,plan.before)
            with store.db:
                store.db.execute('UPDATE remediation SET status=? WHERE receipt=?',('failed',receipt))
            raise
    finally: os.close(fd)


def rollback(store, receipt):
    row=store.db.execute('SELECT plan,status,after_ctime FROM remediation WHERE receipt=?',(receipt,)).fetchone()
    if not row or row[1] not in ('applied','prepared'): raise ValueError('receipt unavailable or consumed')
    plan=Plan(**json.loads(row[0]))
    if plan.action_id!=ACTION_ID: raise ValueError('invalid receipt action')
    fd=open_dir(account_home())
    try:
        uid,dev,ino,ctime,mode=identity(fd)
        if (uid,dev,ino,mode)!=(plan.uid,plan.device,plan.inode,plan.after) or row[2] is not None and ctime!=row[2]:
            raise ValueError('rollback target changed')
        current=open_dir(account_home())
        try:
            if identity(current)!=identity(fd): raise ValueError('rollback identity changed')
        finally: os.close(current)
        os.fchmod(fd,plan.before)
        try:
            if identity(fd)[-1]!=plan.before: raise ValueError('rollback postcondition failed')
            with store.db:
                store.db.execute('UPDATE remediation SET status=?, finished_at=? WHERE receipt=?',('rolled_back',now(),receipt))
        except BaseException:
            if identity(fd)[-1]==plan.before: os.fchmod(fd,plan.after)
            raise
    finally: os.close(fd)


def journal(store):
    rows=store.db.execute('SELECT receipt,status,created_at,finished_at FROM remediation ORDER BY created_at DESC LIMIT 32').fetchall()
    return [{'receipt':r[0],'status':r[1],'created_at':r[2],'finished_at':r[3]} for r in rows]
