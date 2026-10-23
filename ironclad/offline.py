"""Linux process-local network guard. Does not change host networking or firewall."""
import ctypes
import errno
from pathlib import Path
import platform
import stat

active = False


class Comparison(ctypes.Structure):
    _fields_ = [('arg',ctypes.c_uint),('op',ctypes.c_int),('datum_a',ctypes.c_uint64),('datum_b',ctypes.c_uint64)]


def restrict():
    global active
    if active: return
    if platform.system()!='Linux' or platform.machine() not in ('x86_64','aarch64'):
        raise ValueError('offline guard unsupported on this architecture')
    candidates = ['/usr/lib/libseccomp.so.2','/usr/lib64/libseccomp.so.2']
    triplet = 'x86_64-linux-gnu' if platform.machine() == 'x86_64' else 'aarch64-linux-gnu'
    candidates.append('/usr/lib/'+triplet+'/libseccomp.so.2')
    path = None
    for candidate in candidates:
        try:
            resolved=Path(candidate).resolve(strict=True)
        except FileNotFoundError:
            continue
        info=resolved.stat()
        if info.st_uid!=0 or info.st_mode & 0o022 or not stat.S_ISREG(info.st_mode):
            raise ValueError('untrusted seccomp library')
        path=resolved
        break
    if path is None: raise FileNotFoundError('system libseccomp unavailable')
    lib=ctypes.CDLL(str(path),use_errno=True)
    lib.seccomp_init.argtypes=[ctypes.c_uint32]; lib.seccomp_init.restype=ctypes.c_void_p
    lib.seccomp_release.argtypes=[ctypes.c_void_p]; lib.seccomp_release.restype=None
    lib.seccomp_syscall_resolve_name.argtypes=[ctypes.c_char_p]; lib.seccomp_syscall_resolve_name.restype=ctypes.c_int
    lib.seccomp_rule_add_array.argtypes=[ctypes.c_void_p,ctypes.c_uint32,ctypes.c_int,ctypes.c_uint,ctypes.POINTER(Comparison)]
    lib.seccomp_rule_add_array.restype=ctypes.c_int
    lib.seccomp_load.argtypes=[ctypes.c_void_p]; lib.seccomp_load.restype=ctypes.c_int
    context=lib.seccomp_init(0x7fff0000)  # SCMP_ACT_ALLOW
    if not context: raise ValueError('seccomp initialization failed')
    try:
        syscall=lib.seccomp_syscall_resolve_name(b'socket')
        if syscall<0: raise ValueError('socket syscall unavailable')
        # Deny creation of Internet sockets. Local Unix desktop IPC and netlink
        # metadata stay available. Inherited sockets/Unix proxies are outside this
        # narrow guard; the engine accepts neither descriptors nor proxy requests.
        for family in (2,10):  # AF_INET, AF_INET6
            arg=Comparison(0,4,family,0)  # SCMP_CMP_EQ
            if lib.seccomp_rule_add_array(context,0x00050000|errno.EPERM,syscall,1,ctypes.byref(arg))<0:
                raise ValueError('seccomp rule failed')
        if lib.seccomp_load(context)<0: raise ValueError('offline guard installation failed')
        active=True
    finally: lib.seccomp_release(context)
