"""Reviewed, fixed diagnostic predicates; no runtime-generated check identities.

Each row names an independent control, not one check per CPU/process/file found.
Tier membership is explicit. Optional controls never become synthetic passes.
"""
from dataclasses import dataclass

KERNEL = 'https://docs.kernel.org/admin-guide/sysctl/kernel.html'
NET = 'https://docs.kernel.org/networking/ip-sysctl.html'
VM = 'https://docs.kernel.org/admin-guide/sysctl/vm.html'
FS = 'https://docs.kernel.org/admin-guide/sysctl/fs.html'
CONFIG = 'https://docs.kernel.org/security/self-protection.html'
SYSTEMD = 'https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html'
MOUNT = 'https://www.kernel.org/doc/html/latest/filesystems/proc.html'

@dataclass(frozen=True)
class Rule:
 id: str
 tier: str
 kind: str
 target: str
 policy: str
 label: str
 reason: str
 doc: str

RULES=[]
def add(tier,kind,target,policy,label,reason,doc):
 identifier=kind+'.'+target.strip('/').replace('/','.').replace('-','_').lower()
 RULES.append(Rule(identifier,tier,kind,target,policy,label,reason,doc))

def sysctls(tier,text):
 for row in text.strip().splitlines():
  target,policy,label,reason=row.split('|')
  doc=NET if target.startswith('net/') else FS if target.startswith('fs/') else VM if target.startswith('vm/') else KERNEL
  add(tier,'sysctl',target,policy,label,reason,doc)

sysctls('quick','''
kernel/kptr_restrict|ge:1|Kernel pointer disclosure|Restrict kernel addresses exposed through formatted kernel interfaces.
kernel/dmesg_restrict|eq:1|Kernel log access|Restrict unprivileged access to kernel log data.
kernel/yama/ptrace_scope|ge:1|Process tracing restrictions|Reduce unrelated-process tracing; debugger workflows may need exceptions.
kernel/unprivileged_bpf_disabled|ge:1|Unprivileged BPF loading|Limit unprivileged kernel bytecode attack surface without disabling privileged Falco.
kernel/perf_event_paranoid|ge:2|Performance counter access|Limit unprivileged profiling of kernel execution.
kernel/kexec_load_disabled|observe|Runtime kernel replacement|Restrict kexec after boot; crash dump and administrator workflows can require it.
kernel/modules_disabled|observe|Runtime module loading|Observe irreversible-until-reboot module lockdown; ordinary desktops commonly need dynamic modules.
kernel/unprivileged_userns_clone|observe|Unprivileged user namespaces|Report namespace exposure; browsers and bubblewrap can require user namespaces, so do not disable automatically.
kernel/sysrq|mask:176|Magic SysRq permissions|Limit debug/control operations while retaining deliberate recovery capabilities.
kernel/printk|observe|Console kernel log level|Inspect console verbosity without collecting any kernel log contents.
fs/protected_hardlinks|eq:1|Hard-link ownership protection|Reduce privileged hard-link attacks against files not owned by the caller.
fs/protected_symlinks|eq:1|Sticky-directory symlink protection|Reduce symlink races in shared sticky directories.
fs/protected_fifos|ge:1|Sticky-directory FIFO protection|Reduce privileged opens of attacker-owned FIFO objects.
fs/protected_regular|ge:1|Sticky-directory regular-file protection|Reduce privileged creation/open races in shared temporary directories.
fs/suid_dumpable|eq:0|Privileged core dumps|Check whether changed-privilege processes may generate sensitive core dumps; managed root-only dumps can be intentional.
vm/mmap_min_addr|ge:65536|Low-address mapping barrier|Limit user mappings at low addresses often involved in null-dereference exploitation.
vm/unprivileged_userfaultfd|eq:0|Unprivileged userfaultfd|Restrict userfaultfd attack surface; some runtimes require explicit exceptions.
vm/mmap_rnd_bits|observe|Native mmap randomization bits|Record the architecture-specific ASLR entropy setting; no universal cross-architecture threshold.
vm/mmap_rnd_compat_bits|observe|Compatibility mmap randomization bits|Record entropy for compatibility processes separately from native mappings.
net/ipv4/tcp_syncookies|ge:1|TCP SYN cookies|Check availability of SYN-flood fallback; not proof of DDoS resistance.
net/ipv4/tcp_rfc1337|eq:1|TCP TIME_WAIT assassination defense|Check protection against a class of premature TIME_WAIT termination.
net/ipv4/icmp_echo_ignore_broadcasts|eq:1|Broadcast ICMP replies|Avoid responding to broadcast echo requests.
net/ipv4/icmp_ignore_bogus_error_responses|eq:1|Bogus ICMP error handling|Suppress bogus broadcast ICMP errors.
net/ipv4/conf/all/accept_redirects|eq:0|IPv4 aggregate redirect acceptance|Review redirect processing policy; effective interface settings require separate review.
net/ipv4/conf/default/accept_redirects|eq:0|IPv4 new-interface redirect policy|Check the template inherited by future interfaces.
net/ipv4/conf/all/send_redirects|eq:0|IPv4 aggregate redirect transmission|Review router redirect behavior; forwarding roles may differ.
net/ipv4/conf/all/accept_source_route|eq:0|IPv4 source routing|Review acceptance of source-routed packets.
net/ipv6/conf/all/accept_redirects|eq:0|IPv6 aggregate redirect acceptance|Review IPv6 redirect policy; interface-specific overrides are not certified.
net/ipv6/conf/default/accept_redirects|eq:0|IPv6 new-interface redirect policy|Check the IPv6 redirect template separately from current aggregate settings.
net/ipv4/conf/all/rp_filter|ge:1|IPv4 reverse-path filtering|Review source validation; asymmetric routing and VPNs may require loose filtering.
''')

sysctls('full','''
net/ipv4/conf/default/send_redirects|eq:0|New-interface IPv4 redirect transmission|Check redirect transmission inherited by new interfaces.
net/ipv4/conf/default/accept_source_route|eq:0|New-interface IPv4 source routing|Check source-routing acceptance inherited by new interfaces.
net/ipv4/conf/default/rp_filter|ge:1|New-interface reverse-path filtering|Check source-validation defaults without changing VPN or router behavior.
net/ipv4/conf/all/secure_redirects|eq:0|IPv4 secure redirect acceptance|Even gateway-listed redirects may alter routing; interpret with accept_redirects.
net/ipv4/conf/default/secure_redirects|eq:0|New-interface secure redirect policy|Check secure-redirect defaults independently of active interfaces.
net/ipv4/conf/all/log_martians|eq:1|IPv4 martian logging|Observe logging of impossible source addresses; busy networks may limit logging.
net/ipv4/conf/default/log_martians|eq:1|New-interface martian logging|Check logging inherited by future IPv4 interfaces.
net/ipv4/conf/all/route_localnet|eq:0|IPv4 loopback routing|Review routing of loopback addresses beyond loopback; container networking may need exceptions.
net/ipv4/conf/all/accept_local|eq:0|IPv4 local-source acceptance|Review externally received packets with local source addresses.
net/ipv4/conf/all/arp_filter|observe|IPv4 ARP reply filtering|Record multihomed ARP behavior; correct values depend on routing topology.
net/ipv4/conf/all/arp_ignore|observe|IPv4 ARP reply selection|Record ARP reply policy without assuming a universal multihoming setting.
net/ipv4/conf/all/arp_announce|observe|IPv4 ARP source selection|Record source-address selection policy for multihomed diagnosis.
net/ipv6/conf/all/accept_source_route|le:0|IPv6 source-route handling|Review routing-header acceptance; disabled protocols are handled separately.
net/ipv6/conf/default/accept_source_route|le:0|New-interface IPv6 source routes|Check future-interface routing-header policy.
net/ipv6/conf/all/accept_ra|observe|IPv6 router advertisements|Record SLAAC/router-advertisement behavior; disabling it can break normal connectivity.
net/ipv6/conf/default/accept_ra|observe|New-interface router advertisements|Record the SLAAC template separately from active interfaces.
net/ipv4/ip_forward|observe|IPv4 forwarding role|Record host/router behavior; containers and VPNs may legitimately enable forwarding.
net/ipv6/conf/all/forwarding|observe|IPv6 forwarding role|Record IPv6 host/router behavior separately from IPv4.
net/core/bpf_jit_harden|ge:1|BPF JIT hardening|Check constant blinding against JIT spraying, accounting for performance tradeoffs.
net/core/bpf_jit_kallsyms|eq:0|BPF JIT symbol exposure|Review visibility of JIT addresses for profiling/debugging.
''')

sysctls('super','''
kernel/core_uses_pid|eq:1|Core-dump PID suffix|Avoid ambiguous legacy core names; piped core handlers have separate naming semantics.
kernel/core_pipe_limit|observe|Concurrent piped core dumps|Record the concurrency bound for core handlers without reading core dumps.
kernel/panic|observe|Panic reboot delay|Record recovery policy; unattended reboot and forensic needs differ.
kernel/panic_on_oops|observe|Oops recovery policy|Record whether kernel oops forces a panic; availability tradeoffs are workload-specific.
kernel/panic_on_warn|observe|Warning panic policy|Record whether warnings force a panic; enabled settings may reduce availability.
kernel/nmi_watchdog|observe|NMI lockup watchdog|Record lockup detection without enabling a watchdog or forcing a failure.
kernel/hung_task_timeout_secs|observe|Hung-task detection timeout|Record blocked-task detection policy without reading task identities.
kernel/softlockup_panic|observe|Soft-lockup recovery|Record panic behavior for scheduler lockups.
kernel/hardlockup_panic|observe|Hard-lockup recovery|Record panic behavior for hard lockups separately from soft lockups.
kernel/io_uring_disabled|observe|io_uring exposure|Review asynchronous-I/O attack surface; runtimes may depend on io_uring, and this scan does not disable it.
kernel/random/entropy_avail|observe|Kernel entropy availability|Record the entropy estimate; this alone does not establish random-number weakness.
kernel/keys/maxkeys|observe|Per-user key-count limit|Inspect keyring resource limits without enumerating keys or reading key material.
kernel/keys/maxbytes|observe|Per-user key-byte limit|Inspect keyring memory limits without reading keys.
fs/pipe-user-pages-hard|observe|Per-user pipe hard limit|Inspect denial-of-service resource bounds; zero may intentionally mean unlimited.
fs/pipe-user-pages-soft|observe|Per-user pipe soft limit|Record the pipe allocation soft limit independently of the hard limit.
fs/pipe-max-size|observe|Maximum unprivileged pipe size|Record per-pipe memory exposure without allocating pipes.
fs/aio-max-nr|observe|Asynchronous-I/O request capacity|Record global AIO capacity without issuing I/O requests.
fs/nr_open|observe|Per-process file-descriptor ceiling|Record the kernel descriptor ceiling; actual process limits are separate.
fs/file-max|observe|Global file-handle ceiling|Record global handle capacity separately from per-process limits.
vm/overcommit_memory|observe|Virtual-memory overcommit policy|Record allocator policy; strict overcommit can break expected workloads.
vm/overcommit_ratio|observe|Overcommit accounting ratio|Record the ratio used by strict overcommit rather than labeling a universal safe value.
vm/swappiness|observe|Swap preference|Record reclaim behavior; appropriate settings depend on swap/zram and workload.
vm/dirty_ratio|observe|Dirty-page writeback ceiling|Inspect dirty-memory limits relevant to stalls and writeback pressure.
vm/dirty_background_ratio|observe|Background dirty-page threshold|Inspect background writeback separately from the hard dirty ratio.
vm/dirty_expire_centisecs|observe|Dirty-page expiration|Record writeback age policy without claiming power-loss durability.
vm/dirty_writeback_centisecs|observe|Periodic writeback cadence|Record flusher cadence separately from page expiration.
vm/max_map_count|observe|Process mapping capacity|Record mapping capacity relevant to large applications and games.
vm/vfs_cache_pressure|observe|Filesystem metadata reclaim preference|Record inode/dentry reclaim policy without recommending blanket tuning.
net/ipv4/tcp_timestamps|observe|TCP timestamp policy|Record timestamp behavior; performance and fingerprinting tradeoffs differ.
net/ipv4/tcp_sack|observe|TCP selective acknowledgments|Record SACK support without applying obsolete blanket-disable advice.
''')

# Metadata only: never open these files or inspect credential/configuration contents.
QUICK_PATHS='''
/etc|System configuration directory
/usr|Packaged userspace root
/usr/bin|Packaged executable directory
/usr/lib|Packaged library directory
/boot|Boot configuration directory
/etc/passwd|Account database metadata
/etc/group|Group database metadata
/etc/shadow|Shadow password database metadata
/etc/gshadow|Shadow group database metadata
/etc/sudoers|Administrator policy metadata
/etc/sudoers.d|Administrator policy directory
/etc/pam.d|Authentication policy directory
/etc/ssh|SSH policy directory
/etc/systemd/system|System service override directory
/etc/cron.d|System cron directory
/etc/sysctl.d|Kernel parameter override directory
/etc/udev/rules.d|Device-rule override directory
/etc/ld.so.preload|Preloaded-library policy metadata
/etc/ld.so.conf|Dynamic loader policy metadata
/etc/pacman.conf|Package manager policy metadata
'''
SUPER_PATHS='''
/etc/polkit-1/rules.d|Authorization rule directory
/usr/share/polkit-1/rules.d|Packaged authorization rules
/usr/lib/systemd/system|Packaged system services
/usr/lib/systemd/user|Packaged user services
/etc/systemd/user|Administrator user-service policy
/etc/modprobe.d|Module parameter overrides
/etc/modules-load.d|Boot module-load overrides
/etc/tmpfiles.d|Temporary-file policy overrides
/etc/NetworkManager|Network manager configuration metadata
/etc/NetworkManager/system-connections|Network profile directory metadata
/etc/ssl/certs|System trust-store directory
/etc/ca-certificates|Certificate policy directory
/etc/security|Login security policy directory
/etc/audit|Audit policy directory
/etc/nftables.conf|Firewall configuration metadata
/etc/iptables|Legacy firewall policy directory
/etc/fstab|Filesystem policy metadata
/etc/crypttab|Encrypted-volume policy metadata
/etc/default/grub|Bootloader defaults metadata
/etc/kernel|Kernel-install policy directory
/usr/local/bin|Locally installed executable directory
/usr/local/lib|Locally installed library directory
/usr/local/sbin|Local administrator executable directory
/usr/sbin|Administrator executable entry directory
/var/lib/pacman|Package database directory metadata
/var/cache/pacman|Package cache parent metadata
/var/log|System log directory metadata
/root|Administrator home directory metadata
/etc/profile|System login profile metadata
/etc/profile.d|System login script directory metadata
'''
for tier,rows in [('quick',QUICK_PATHS),('super',SUPER_PATHS)]:
 for row in rows.strip().splitlines():
  target,label=row.split('|')
  add(tier,'metadata',target,'root_no_write',label,'Check root ownership and absence of group/world write access using metadata only; an intentional delegated directory needs local review. Symlink targets are evaluated, not file contents.', 'https://man7.org/linux/man-pages/man2/stat.2.html')

KCONFIG_QUICK='''
STRICT_KERNEL_RWX|Kernel code/data permissions|Separate writable data from executable kernel code.
STRICT_MODULE_RWX|Module code/data permissions|Apply write/execute separation to loadable kernel modules.
STACKPROTECTOR_STRONG|Kernel stack canaries|Instrument vulnerable stack layouts against overwrite exploitation.
VMAP_STACK|Guarded kernel stacks|Use virtually mapped stacks with guard-page overflow detection.
THREAD_INFO_IN_TASK|Separated thread metadata|Keep thread metadata away from the kernel stack.
HARDENED_USERCOPY|Hardened user copies|Check object boundaries during kernel/user memory copies.
FORTIFY_SOURCE|Fortified kernel memory operations|Add compile-time/runtime checks to supported memory operations.
LIST_HARDENED|Linked-list integrity|Check list operations for corruption.
BUG_ON_DATA_CORRUPTION|Corruption fail-stop support|Observe fail-stop behavior for detected corruption; availability costs need review.
SHUFFLE_PAGE_ALLOCATOR|Page allocator shuffling|Reduce predictability of physical-page reuse where enabled at runtime.
SLAB_FREELIST_RANDOM|Slab freelist randomization|Reduce allocator reuse predictability.
SLAB_FREELIST_HARDENED|Slab freelist integrity|Harden allocator metadata against exploitation.
INIT_ON_ALLOC_DEFAULT_ON|Allocation initialization default|Reduce uninitialized heap data exposure; runtime overrides may differ.
INIT_ON_FREE_DEFAULT_ON|Freed-memory clearing default|Reduce stale heap data lifetime; runtime overrides may differ.
ZERO_CALL_USED_REGS|Call-used register clearing|Reduce stale register data after function return where compiler support exists.
'''
KCONFIG_FULL='''
SECURITY_DMESG_RESTRICT|Restricted kernel-log default|Build in restricted dmesg defaults; live sysctl is checked separately.
BPF_UNPRIV_DEFAULT_OFF|Unprivileged BPF default|Build in restricted unprivileged BPF defaults; live sysctl is checked separately.
SECURITY_YAMA|Yama security module support|Provide ptrace restriction support; module activation is separate.
SECURITY_LANDLOCK|Landlock sandbox support|Provide application-managed sandboxing support; applications must opt in.
SECCOMP|Secure computing support|Provide process syscall restriction support.
SECCOMP_FILTER|Syscall filter support|Provide programmable process syscall filtering; this does not prove every process uses it.
RANDOMIZE_BASE|Kernel address randomization support|Provide kernel image address randomization; runtime overrides may differ.
RANDOMIZE_MEMORY|Kernel memory-region randomization|Provide additional kernel-region layout randomization.
X86_UMIP|User-mode instruction prevention support|Restrict selected sensitive instructions on supported x86 processors.
'''
KCONFIG_SUPER='''
SECURITY|Security hook framework|Provide Linux security-module hooks.
SECURITYFS|Security policy filesystem support|Expose security-module control interfaces when mounted.
SECURITY_APPARMOR|AppArmor support|Provide path-based confinement support; loaded policy enforcement is separate.
SECURITY_SELINUX|SELinux support|Provide label-based confinement support; loaded policy enforcement is separate.
SECURITY_SMACK|Smack support|Provide Smack confinement where a deployment uses it.
SECURITY_TOMOYO|TOMOYO support|Provide TOMOYO policy support where deployed.
SECURITY_LOCKDOWN_LSM|Kernel lockdown support|Provide lockdown hooks; active lockdown is a runtime decision.
LOCK_DOWN_KERNEL_FORCE_INTEGRITY|Forced integrity lockdown build policy|Observe build-time integrity lockdown, distinct from merely compiling lockdown support.
LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY|Forced confidentiality lockdown build policy|Observe build-time confidentiality lockdown; debugging compatibility differs.
MODULE_SIG|Kernel module signature verification support|Provide cryptographic module signature checks.
MODULE_SIG_FORCE|Mandatory module signature build policy|Require trusted module signatures by build policy; custom modules need signing.
MODULE_SIG_ALL|Build-time module signing|Observe whether the build signs all installed modules; enforcement is separate.
MODULE_SIG_SHA256|SHA-256 module signing|Observe the selected module signing hash option, not proof of trusted key provenance.
IMA|Integrity measurement support|Provide integrity measurement support; runtime policy and attestation are separate.
IMA_APPRAISE|Integrity appraisal support|Provide file-integrity appraisal support; loaded appraisal policy is separate.
EVM|Extended verification support|Provide metadata-integrity verification support where keys and policy are configured.
INTEGRITY|Kernel integrity framework|Provide the common integrity framework used by measurement/appraisal.
INTEGRITY_SIGNATURE|Integrity signature support|Provide integrity-signature verification support.
INTEGRITY_ASYMMETRIC_KEYS|Asymmetric integrity keys|Provide asymmetric verification keys for the integrity subsystem.
AUDIT|Kernel audit support|Provide audit event generation; auditd state and rule coverage are separate.
AUDITSYSCALL|Syscall audit support|Provide syscall auditing hooks.
RANDSTRUCT_FULL|Full structure layout randomization|Observe full structure layout randomization; compiler and module compatibility matter.
RANDSTRUCT_PERFORMANCE|Selective structure layout randomization|Observe the alternative performance-oriented layout randomization mode.
GCC_PLUGIN_RANDSTRUCT|GCC structure randomization support|Record compiler-plugin support where the kernel uses this option.
GCC_PLUGIN_LATENT_ENTROPY|Latent entropy instrumentation|Record additional entropy instrumentation; this alone is not RNG validation.
INIT_STACK_ALL_ZERO|Zero-initialized stack variables|Observe compiler automatic-variable zero initialization.
INIT_STACK_ALL_PATTERN|Pattern-initialized stack variables|Observe the alternative pattern initialization mode, not a required parallel mode.
KSTACK_ERASE|Kernel stack erasure|Provide stack clearing on syscall return where runtime policy enables it.
RANDOMIZE_KSTACK_OFFSET_DEFAULT|Random kernel-stack offset default|Observe the default stack-offset randomization policy; runtime overrides may differ.
SCHED_CORE|Core scheduling support|Provide same-core workload separation support; this does not prove active core cookies.
X86_USER_SHADOW_STACK|Userspace shadow stack support|Provide x86 userspace shadow-stack support; applications must enable it.
X86_KERNEL_IBT|Kernel indirect branch tracking|Provide kernel control-flow landing-pad checks on supported x86 hardware.
CFI_CLANG|Clang control-flow integrity|Observe compiler control-flow checks where supported.
CFI_PERMISSIVE|Permissive control-flow checks|Record permissive CFI mode, which can report rather than halt violations.
SHADOW_CALL_STACK|Shadow call stack support|Provide a protected return-address stack on supported architectures.
ARM64_PTR_AUTH|ARM64 pointer authentication|Provide pointer authentication support on applicable hardware.
ARM64_BTI_KERNEL|ARM64 kernel branch target identification|Provide ARM64 kernel indirect-branch landing-pad checks.
ARM64_MTE|ARM64 memory tagging support|Provide hardware memory tagging support; applications/runtime policy determine use.
ARM64_SW_TTBR0_PAN|ARM64 software PAN fallback|Provide software PAN where selected for supported ARM64 configurations.
MITIGATION_PAGE_TABLE_ISOLATION|Page-table isolation mitigation option|Observe newer-kernel page-table isolation support where this symbol exists.
MITIGATION_RETPOLINE|Retpoline mitigation option|Observe newer-kernel retpoline support where this symbol exists.
MITIGATION_RETHUNK|Return thunk mitigation option|Provide return-thunk mitigation support where supported.
MITIGATION_UNRET_ENTRY|Entry return predictor mitigation|Provide entry-time return predictor untraining support.
MITIGATION_CALL_DEPTH_TRACKING|Call-depth tracking mitigation|Provide call-depth-based return prediction mitigation support.
MITIGATION_IBPB_ENTRY|Entry indirect branch predictor barrier|Provide predictor barrier mitigation support on applicable processors.
MITIGATION_SRSO|Speculative return stack overflow mitigation|Provide SRSO mitigation support where applicable.
MITIGATION_SPECTRE_BHI|Branch history injection mitigation|Provide BHI mitigation support where applicable.
MITIGATION_RFDS|Register file data sampling mitigation|Provide RFDS mitigation support where applicable.
MITIGATION_MDS|Microarchitectural data sampling mitigation|Provide MDS mitigation support where applicable.
MITIGATION_TAA|TSX asynchronous abort mitigation|Provide TAA mitigation support where applicable.
MITIGATION_MMIO_STALE_DATA|MMIO stale data mitigation|Provide MMIO stale-data mitigation support where applicable.
MITIGATION_L1TF|L1 terminal fault mitigation|Provide L1TF mitigation support where applicable.
'''
KCONFIG_SOURCES={'STRICT_KERNEL_RWX': 'arch/Kconfig', 'STRICT_MODULE_RWX': 'arch/Kconfig', 'STACKPROTECTOR_STRONG': 'arch/Kconfig', 'VMAP_STACK': 'arch/Kconfig', 'THREAD_INFO_IN_TASK': 'init/Kconfig', 'HARDENED_USERCOPY': 'security/Kconfig.hardening', 'FORTIFY_SOURCE': 'security/Kconfig.hardening', 'LIST_HARDENED': 'security/Kconfig.hardening', 'BUG_ON_DATA_CORRUPTION': 'security/Kconfig.hardening', 'SHUFFLE_PAGE_ALLOCATOR': 'mm/Kconfig', 'SLAB_FREELIST_RANDOM': 'mm/Kconfig', 'SLAB_FREELIST_HARDENED': 'mm/Kconfig', 'INIT_ON_ALLOC_DEFAULT_ON': 'security/Kconfig.hardening', 'INIT_ON_FREE_DEFAULT_ON': 'security/Kconfig.hardening', 'ZERO_CALL_USED_REGS': 'security/Kconfig.hardening', 'SECURITY_DMESG_RESTRICT': 'security/Kconfig', 'BPF_UNPRIV_DEFAULT_OFF': 'kernel/bpf/Kconfig', 'SECURITY_YAMA': 'security/yama/Kconfig', 'SECURITY_LANDLOCK': 'security/landlock/Kconfig', 'SECCOMP': 'arch/Kconfig', 'SECCOMP_FILTER': 'arch/Kconfig', 'RANDOMIZE_BASE': 'arch/arm64/Kconfig', 'RANDOMIZE_MEMORY': 'arch/x86/Kconfig', 'X86_UMIP': 'arch/x86/Kconfig', 'SECURITY': 'security/Kconfig', 'SECURITYFS': 'security/Kconfig', 'SECURITY_APPARMOR': 'security/apparmor/Kconfig', 'SECURITY_SELINUX': 'security/selinux/Kconfig', 'SECURITY_SMACK': 'security/smack/Kconfig', 'SECURITY_TOMOYO': 'security/tomoyo/Kconfig', 'SECURITY_LOCKDOWN_LSM': 'security/lockdown/Kconfig', 'LOCK_DOWN_KERNEL_FORCE_INTEGRITY': 'security/lockdown/Kconfig', 'LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY': 'security/lockdown/Kconfig', 'MODULE_SIG': 'kernel/module/Kconfig', 'MODULE_SIG_FORCE': 'kernel/module/Kconfig', 'MODULE_SIG_ALL': 'kernel/module/Kconfig', 'MODULE_SIG_SHA256': 'kernel/module/Kconfig', 'IMA': 'security/integrity/ima/Kconfig', 'IMA_APPRAISE': 'security/integrity/ima/Kconfig', 'EVM': 'security/integrity/evm/Kconfig', 'INTEGRITY': 'security/integrity/Kconfig', 'INTEGRITY_SIGNATURE': 'security/integrity/Kconfig', 'INTEGRITY_ASYMMETRIC_KEYS': 'security/integrity/Kconfig', 'AUDIT': 'init/Kconfig', 'AUDITSYSCALL': 'init/Kconfig', 'RANDSTRUCT_FULL': 'security/Kconfig.hardening', 'RANDSTRUCT_PERFORMANCE': 'security/Kconfig.hardening', 'GCC_PLUGIN_RANDSTRUCT': 'security/Kconfig.hardening', 'GCC_PLUGIN_LATENT_ENTROPY': 'scripts/gcc-plugins/Kconfig', 'INIT_STACK_ALL_ZERO': 'security/Kconfig.hardening', 'INIT_STACK_ALL_PATTERN': 'security/Kconfig.hardening', 'KSTACK_ERASE': 'security/Kconfig.hardening', 'RANDOMIZE_KSTACK_OFFSET_DEFAULT': 'arch/Kconfig', 'SCHED_CORE': 'kernel/Kconfig.preempt', 'X86_USER_SHADOW_STACK': 'arch/x86/Kconfig', 'X86_KERNEL_IBT': 'arch/x86/Kconfig', 'CFI_CLANG': 'arch/Kconfig', 'CFI_PERMISSIVE': 'arch/Kconfig', 'SHADOW_CALL_STACK': 'arch/Kconfig', 'ARM64_PTR_AUTH': 'arch/arm64/Kconfig', 'ARM64_BTI_KERNEL': 'arch/arm64/Kconfig', 'ARM64_MTE': 'arch/arm64/Kconfig', 'ARM64_SW_TTBR0_PAN': 'arch/arm64/Kconfig', 'MITIGATION_PAGE_TABLE_ISOLATION': 'arch/x86/Kconfig', 'MITIGATION_RETPOLINE': 'arch/x86/Kconfig', 'MITIGATION_RETHUNK': 'arch/x86/Kconfig', 'MITIGATION_UNRET_ENTRY': 'arch/x86/Kconfig', 'MITIGATION_CALL_DEPTH_TRACKING': 'arch/x86/Kconfig', 'MITIGATION_IBPB_ENTRY': 'arch/x86/Kconfig', 'MITIGATION_SRSO': 'arch/x86/Kconfig', 'MITIGATION_SPECTRE_BHI': 'arch/x86/Kconfig', 'MITIGATION_RFDS': 'arch/x86/Kconfig', 'MITIGATION_MDS': 'arch/x86/Kconfig', 'MITIGATION_TAA': 'arch/x86/Kconfig', 'MITIGATION_MMIO_STALE_DATA': 'arch/x86/Kconfig', 'MITIGATION_L1TF': 'arch/x86/Kconfig'}
CORE_BUILD_CONTROLS={
 'STRICT_KERNEL_RWX','STRICT_MODULE_RWX','STACKPROTECTOR_STRONG','VMAP_STACK',
 'THREAD_INFO_IN_TASK','HARDENED_USERCOPY','FORTIFY_SOURCE','LIST_HARDENED',
 'SLAB_FREELIST_RANDOM','SLAB_FREELIST_HARDENED','SECCOMP','SECCOMP_FILTER',
 'RANDOMIZE_BASE','RANDOMIZE_MEMORY','SECURITY',
}
for tier,rows in [('quick',KCONFIG_QUICK),('full',KCONFIG_FULL),('super',KCONFIG_SUPER)]:
 for row in rows.strip().splitlines():
  target,label,reason=row.split('|')
  # These are build-feature observations, not recommendations to enable every
  # mutually exclusive LSM/compiler/architecture option.
  add(tier,'kconfig',target,'enabled' if target in CORE_BUILD_CONTROLS else 'observe',label,reason+' Build evidence is not runtime enforcement.','https://github.com/torvalds/linux/blob/master/'+KCONFIG_SOURCES[target])

# Runtime CPU vulnerability classes complement build-feature observations.
for tier,target,label in [
 ('full','spectre_v1','Spectre v1 runtime mitigation'),
 ('full','spectre_v2','Spectre v2 runtime mitigation'),
 ('full','meltdown','Meltdown runtime mitigation'),
 ('super','spec_store_bypass','Speculative store bypass runtime mitigation'),
 ('super','l1tf','L1 terminal fault runtime mitigation'),
 ('super','mds','Microarchitectural data sampling runtime mitigation'),
 ('super','tsx_async_abort','TSX asynchronous abort runtime mitigation'),
 ('super','itlb_multihit','Instruction TLB multihit runtime mitigation'),
 ('super','srbds','Special register buffer data sampling runtime mitigation'),
 ('super','mmio_stale_data','MMIO stale data runtime mitigation'),
 ('super','retbleed','Retbleed runtime mitigation')]:
 add(tier,'cpu_mitigation',target,'mitigation',label,'Inspect the running kernel mitigation report for this CPU vulnerability class; mitigation does not certify exploit resistance or cover every CPU vulnerability.', 'https://docs.kernel.org/admin-guide/hw-vuln/index.html')

for target,label in [('falco','Behavior monitor health'),('automatic','Automatic Downloads scanner health'),('manual','One-off scanner readiness'),('signatures','One-off signature freshness'),('updates','Automatic protection maintenance health')]:
 add('quick','protection',target,'healthy',label,'Verify actual protection readiness; installed binaries alone do not establish active coverage.', 'https://docs.clamav.net/manual/Usage/Scanning.html' if target!='falco' else 'https://falco.org/docs/')

for target,flags in [('/tmp','nosuid nodev noexec'),('/var/tmp','nosuid nodev noexec'),('/dev/shm','nosuid nodev noexec'),('/run','nosuid nodev'),('/boot','nosuid nodev noexec'),('/efi','nosuid nodev noexec'),('/proc','nosuid nodev noexec')]:
 for flag in flags.split():
  add('full','mount',target+'/'+flag,flag,f'{target}: {flag} mount restriction',{'nosuid':'Prevent set-ID and file capability elevation on this mount.','nodev':'Prevent device-node interpretation on this mount.','noexec':'Restrict direct executable loading on this mount; interpreters can still read scripts, and installers may need execution.'}[flag]+' Effective covering mount is evaluated; no mount changes.',MOUNT)

# Separate service/property pairs are distinct isolation controls. Missing,
# inactive or unsupported services never count as passes. Exceptions are advisory.
SERVICE_PROPERTIES='''
NoNewPrivileges|bool|Prevent privilege gain on exec|Limit set-ID and capability privilege acquisition after service start.
ProtectSystem|protectsystem|System filesystem write barrier|Restrict service writes to OS/package files; explicit writable exceptions still matter.
ProtectHome|protecthome|Home directory access barrier|Limit service access to private home data; authenticated login/printing roles may need exceptions.
PrivateTmp|bool|Private temporary directories|Separate service temporary files from shared host temporary paths.
PrivateDevices|bool|Private device view|Reduce service access to host devices; device-facing services may need exceptions.
ProtectKernelTunables|bool|Kernel tunable write barrier|Restrict service access to kernel configuration interfaces.
ProtectKernelModules|bool|Module control barrier|Restrict kernel-module loading and unloading from the service.
ProtectKernelLogs|bool|Kernel log isolation|Restrict access to kernel logs from a compromised service.
ProtectControlGroups|bool|Control-group write barrier|Restrict service changes to cgroup policy.
ProtectClock|bool|Clock modification barrier|Restrict time-setting interfaces and clock device access.
ProtectHostname|bool|Hostname modification barrier|Restrict changes to hostname/domain-name identity.
RestrictSUIDSGID|bool|Set-ID creation restriction|Prevent creation of setuid/setgid files by this service.
RestrictRealtime|bool|Real-time scheduling restriction|Reduce scheduler denial-of-service capability.
RestrictNamespaces|namespaces|Namespace creation restriction|Reduce unnecessary namespace creation/entry; sandboxing services may need exceptions.
LockPersonality|bool|Execution personality lock|Restrict alternate execution personality changes.
MemoryDenyWriteExecute|bool|Writable/executable mapping restriction|Limit simultaneous writable and executable mappings; JIT workloads may need exceptions.
RemoveIPC|observe|IPC lifecycle cleanup|Observe IPC cleanup on service-user exit; shared IPC can need exceptions.
PrivateNetwork|observe|Network namespace isolation|Separate service networking; network-facing services naturally require access or explicit sockets.
PrivateUsers|bool|User namespace isolation|Limit host user identity exposure; kernel support and service roles differ.
ProtectProc|protectproc|Other-process visibility restriction|Limit access to process metadata belonging to other users.
ProcSubset|procsubset|Process-only procfs view|Hide non-process procfs interfaces from the service where appropriate.
UMask|umask|Created-file permission mask|Check whether newly created files default to excluding access by other users.
User|observe|Unprivileged service identity|Reduce ambient root authority; root management and login services can need privileges.
DynamicUser|observe|Ephemeral service identity|Observe dynamic identity allocation; static dedicated accounts are a valid alternative.
CapabilityBoundingSet|caps|Capability ceiling|Observe whether the service has a narrower capability ceiling than all kernel capabilities.
AmbientCapabilities|ambient|Ambient privilege propagation|Review nonempty ambient capabilities inherited by executed programs.
RestrictAddressFamilies|families|Socket-family restriction|Observe allowlisting of address families; broad networking requirements can be intentional.
SystemCallFilter|filter|Syscall filtering policy|Observe nonempty syscall filter policy; presence alone does not measure filter completeness.
SystemCallArchitectures|arch|Syscall ABI restriction|Observe an allowed architecture list; compatibility executables may require multiple ABIs.
KeyringMode|keyring|Service keyring isolation|Observe private service keyring policy without reading any keys.
RestrictFileSystems|filesystems|Filesystem type restriction|Observe filesystem type restriction support/policy; ordinary filesystems still need access.
'''
for unit in ('sshd.service','cups.service','avahi-daemon.service','ironclad-antimalware-engine.service'):
 for index,row in enumerate(SERVICE_PROPERTIES.strip().splitlines()):
  prop,policy,label,reason=row.split('|')
  add('full' if index<6 else 'super','service',unit+'/'+prop,policy,unit+': '+label,reason+' Read-only configured policy; application needs and runtime exceptions require review.',SYSTEMD)

for proto,entries in [('tcp',[(21,'FTP'),(22,'SSH'),(23,'Telnet'),(25,'SMTP'),(53,'DNS'),(111,'RPC'),(139,'NetBIOS session'),(445,'SMB'),(3389,'Remote desktop'),(5900,'VNC')]),('udp',[(53,'DNS'),(67,'DHCP server'),(69,'TFTP'),(111,'RPC'),(123,'NTP'),(137,'NetBIOS names'),(138,'NetBIOS datagrams'),(161,'SNMP'),(1900,'SSDP'),(5353,'mDNS')])]:
 for port,label in entries:
  add('super','listener',proto+'/'+str(port),'nonloopback',f'{label} {proto.upper()} port {port} exposure','Check non-loopback listening scope; a port number does not identify the application or prove external reachability. Review intended service and firewall policy.', 'https://www.kernel.org/doc/html/latest/networking/index.html')

RULES=tuple(RULES)
PROFILE_COUNTS={'quick':90,'full':180,'super':420}
TIERS={'quick':('quick',),'full':('quick','full'),'super':('quick','full','super')}

def selected(profile):
 if profile not in TIERS:raise ValueError('unsupported scan profile')
 return tuple(r for r in RULES if r.tier in TIERS[profile])

LEGACY_QUICK='''
system.os|Operating system and kernel inventory|Read OS release metadata and uname, never user identity.
performance.cpu.load|CPU load and capacity|Compare load average with logical CPU capacity; one sample is advisory.
performance.memory|Memory headroom|Compare available memory against total memory.
system.disk.free_space|Root filesystem headroom|Assess available blocks and inodes using statvfs.
security.home.permissions|Home write permissions|Inspect directory metadata for other-user write access; do not read home contents.
security.kernel.aslr|Full userspace ASLR|Read randomize_va_space and check the full-randomization setting.
performance.pressure.memory|Memory pressure|Read memory stall counters; one observation does not prove sustained pressure.
system.uptime|System uptime|Read elapsed uptime without identifying running applications.
startup.units.user_failed|Failed user services|Query failed-unit counts with safe platform names only.
startup.units.system_failed|Failed system services|Query system failed-unit counts independently of user services.
startup.boot|Boot duration|Query systemd boot timing; boot speed alone is not a safety verdict.
packages.installed|Installed package inventory|Count package-manager inventory without reading package database contents directly.
packages.foreign|Foreign package inventory|Count packages outside current sync databases; foreign does not mean malicious.
packages.cached_updates|Cached package updates|Query local cached update metadata; zero does not prove freshness or absence of advisories.
network.listeners|Listening socket inventory|Record protocol, port and bind scope; never retain addresses or process identities.
storage.filesystems|Filesystem and crypt-mapping visibility|Query filesystem types and encryption-container visibility, not encryption assurance.
recovery.backup.discovery|Backup tool discovery|Discover supported binaries; backup success and restore ability remain unverified.
security.persistence.inventory|Startup persistence inventory|Count fixed startup directories without reading their contents.
security.boot.secure_boot|UEFI Secure Boot state|Read the firmware SecureBoot variable when available; no TPM mutation.
hardware.thermal|Thermal sensor readings|Read bounded sysfs temperatures without claiming universal vendor thresholds.
'''
LEGACY_FULL='''
security.lsm|Active security-module names|Read the kernel LSM list; loaded module names alone do not prove policy enforcement.
network.counters|Network byte counters|Read aggregate interface counters without addresses or traffic contents.
network.resolver|Resolver configuration presence|Count nameserver entries without retaining addresses or search domains; no online DNS probe.
security.process.metadata|Running executable metadata|Bounded process executable metadata only; never read arguments, environment or memory.
security.privileged_binaries|Set-ID executable inventory|Bounded nonrecursive executable metadata inventory; presence alone is not malicious.
developer.container.access|Docker privilege exposure|Check caller group and socket metadata without querying containers.
hardware.firmware.support|Firmware update client discovery|Inspect supported client presence; no feed query or firmware changes.
hardware.battery|Battery readings|Read battery capacity/status where applicable; not a design-health certification.
storage.package_cache|Package rollback cache inventory|Count bounded package cache metadata; retained versions are not declared safe to delete.
startup.units.enabled|Enabled user services|Query enabled unit counts without recommending blanket disablement.
startup.timers|User timer inventory|Query timer counts without changing schedules.
hardware.power.profile|Active power profile|Query the current power profile without changing it.
network.clock|Clock synchronization|Query systemd synchronization state; no remote network test.
hardware.gpu|Display controller inventory|Count PCI display controllers; driver acceleration remains unverified.
'''

def inventory(profile='super'):
 if profile not in TIERS:raise ValueError('unsupported scan profile')
 rows=[]
 for tier,text in [('quick',LEGACY_QUICK),('full',LEGACY_FULL)]:
  if tier not in TIERS[profile]:continue
  for line in text.strip().splitlines():
   identifier,label,reason=line.split('|')
   rows.append({'id':identifier,'tier':tier,'kind':'existing','label':label,'target':identifier,'policy':'explicit legacy collector','reason':reason,'documentation':'https://docs.kernel.org/admin-guide/index.html'})
 rows.extend({'id':r.id,'tier':r.tier,'kind':r.kind,'label':r.label,'target':r.target,'policy':r.policy,'reason':r.reason,'documentation':r.doc} for r in selected(profile))
 if len(rows)!=PROFILE_COUNTS[profile] or len({r['id'] for r in rows})!=len(rows):raise ValueError('catalog count/identity mismatch')
 return {'schema':1,'profile':profile,'catalog_checks':len(rows),'checks':rows,'meaning':'Catalog membership is not a passing result. Assessments, observations, unavailable and not-applicable outcomes remain distinct.'}
