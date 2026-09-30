#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/capability.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <ftw.h>
#include <seccomp.h>
#include <signal.h>
#include <sched.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#ifndef TIOCSTI
#define TIOCSTI 0x5412
#endif

#ifndef AF_NETLINK
#define AF_NETLINK 16
#endif

#ifndef NETLINK_SOCK_DIAG
#define NETLINK_SOCK_DIAG 4
#endif

// Landlock MAC Kernel compatibility definitions
#ifndef LANDLOCK_CREATE_RULESET_VERSION
#define LANDLOCK_CREATE_RULESET_VERSION (1U << 0)
#endif

#ifndef SYS_landlock_create_ruleset
#if defined(__x86_64__)
#define SYS_landlock_create_ruleset 444
#define SYS_landlock_add_rule 445
#define SYS_landlock_restrict_self 446
#elif defined(__aarch64__)
#define SYS_landlock_create_ruleset 444
#define SYS_landlock_add_rule 445
#define SYS_landlock_restrict_self 446
#elif defined(__i386__)
#define SYS_landlock_create_ruleset 444
#define SYS_landlock_add_rule 445
#define SYS_landlock_restrict_self 446
#else
#define SYS_landlock_create_ruleset 444
#define SYS_landlock_add_rule 445
#define SYS_landlock_restrict_self 446
#endif
#endif

#ifndef LANDLOCK_RULE_PATH_BENEATH
#define LANDLOCK_RULE_PATH_BENEATH 1
#endif

#ifndef LANDLOCK_RULE_NET_PORT
#define LANDLOCK_RULE_NET_PORT 2
#endif

#ifndef LANDLOCK_ACCESS_NET_BIND_TCP
#define LANDLOCK_ACCESS_NET_BIND_TCP (1ULL << 0)
#define LANDLOCK_ACCESS_NET_CONNECT_TCP (1ULL << 1)
#endif

struct ghostbox_landlock_ruleset_attr {
	__u64 handled_access_fs;
	__u64 handled_access_net;
};

struct ghostbox_landlock_path_beneath_attr {
	__u64 allowed_access;
	__s32 parent_fd;
};

struct ghostbox_landlock_net_port_attr {
	__u64 allowed_access;
	__u64 port;
};

#ifndef LANDLOCK_ACCESS_FS_EXECUTE
#define LANDLOCK_ACCESS_FS_EXECUTE (1ULL << 0)
#define LANDLOCK_ACCESS_FS_WRITE_FILE (1ULL << 1)
#define LANDLOCK_ACCESS_FS_READ_FILE (1ULL << 2)
#define LANDLOCK_ACCESS_FS_READ_DIR (1ULL << 3)
#define LANDLOCK_ACCESS_FS_REMOVE_DIR (1ULL << 4)
#define LANDLOCK_ACCESS_FS_REMOVE_FILE (1ULL << 5)
#define LANDLOCK_ACCESS_FS_MAKE_CHAR (1ULL << 6)
#define LANDLOCK_ACCESS_FS_MAKE_DIR (1ULL << 7)
#define LANDLOCK_ACCESS_FS_MAKE_REG (1ULL << 8)
#define LANDLOCK_ACCESS_FS_MAKE_SOCK (1ULL << 9)
#define LANDLOCK_ACCESS_FS_MAKE_FIFO (1ULL << 10)
#define LANDLOCK_ACCESS_FS_MAKE_BLOCK (1ULL << 11)
#define LANDLOCK_ACCESS_FS_MAKE_SYM (1ULL << 12)
#define LANDLOCK_ACCESS_FS_REFER (1ULL << 13)
#define LANDLOCK_ACCESS_FS_TRUNCATE (1ULL << 14)
#define LANDLOCK_ACCESS_FS_IOCTL_DEV (1ULL << 15)
#endif

// Blocked hardware, sensitive device nodes, and PCI paths enforcement reference
static const char * const BLOCKAGE_BLOCKED_PATHS[] = {
	"/sys/bus/pci/devices",
	"/sys/bus/pci/devices/0000:00:1f.0/config",
	"/proc/bus/pci",
	"/proc/cpuinfo",
	"/proc/meminfo",
	"/sys/devices",
	"/proc/version",
	"/proc/cmdline",
	"/proc/modules",
	"/etc/os-release",
	"/usr/lib/os-release",
	"/sys/firmware",
	"/sys/class/dmi",
	"/boot",
	"/dev/mem",
	"/dev/kmem",
	"/dev/port",
	"/dev/console",
	"/dev/tty",
	"/dev/tty0",
	"/dev/kmsg",
	"/dev/core",
	"/dev/fuse",
	"/dev/kvm",
	"/dev/vhost-net",
	"/dev/vhost-vsock",
	"/dev/loop-control",
	"/home",
	"/root",
	"/media",
	"/mnt",
	"/srv",
	"/etc/iproute2/rt_tables",
	"/etc/resolv.conf",
	"/etc/NetworkManager/NetworkManager.conf",
	"/sys/class/net",
	"/proc/net/dev",
	"/etc/shadow",
	"/etc/passwd",
	"/etc/group"
};

static int blockage_unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
	int rv = remove(fpath);
	return rv;
}

// Secure scratch space cleanup helper preventing symlink attacks and tree traversal races
static void safe_shm_cleanup(const char *path, int (*cb)(const char *, const struct stat *, int, struct FTW *)) {
	struct stat st;
	if (lstat(path, &st) == 0) {
		if (S_ISLNK(st.st_mode)) {
			unlink(path);
		} else if (S_ISDIR(st.st_mode)) {
			chmod(path, 0700);
			nftw(path, cb, 64, FTW_DEPTH | FTW_PHYS);
			remove(path);
		} else {
			unlink(path);
		}
	}
}

// Secure RAM wiper for blockage module with full directory unlinking and removal
void blockage_secure_memory_wipe(void) {
	sigset_t mask, oldmask;
	sigfillset(&mask);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);
	
	umount2("/dev/shm/ghostbox_pivot", MNT_DETACH);
	umount2("/dev/shm/ghostbox_wayland", MNT_DETACH);
	umount2("/dev/shm/ghostbox_home", MNT_DETACH);
	umount2("/dev/shm/ghostbox_root", MNT_DETACH);
	umount2("/dev/shm/ghostbox_resolv.conf", MNT_DETACH);
	umount2("/dev/shm/ghostbox_cpuinfo", MNT_DETACH);
	
	safe_shm_cleanup("/dev/shm/ghostbox_root", blockage_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_home", blockage_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_pivot", blockage_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_wayland", blockage_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_resolv.conf", blockage_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_cpuinfo", blockage_unlink_cb);
	
	size_t alloc_size = 4 * 1024 * 1024;
	void *p = mmap(NULL, alloc_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (p != MAP_FAILED) {
		volatile char *vp = (volatile char *)p;
		for (size_t i = 0; i < alloc_size; i++) {
			vp[i] = 0;
		}
		madvise(p, alloc_size, MADV_DONTNEED);
		munmap(p, alloc_size);
	}
	
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
}

// Blockage Killswitch trigger
void blockage_killswitch(void) {
	fprintf(stderr, "[-] Blockage: Killswitch engaged due to hardening or Seccomp failure.\n");
	blockage_secure_memory_wipe();
	_exit(1);
}

int drop_all_capabilities(void) {
	for (int i = 0; i <= 63; i++) {
		prctl(PR_CAPBSET_DROP, i);
	}
	
	cap_t caps = cap_init();
	if (!caps) {
		perror("GhostBox: cap_init failed");
		return -1;
	}
	if (cap_clear(caps) < 0) {
		perror("GhostBox: cap_clear failed");
		cap_free(caps);
		return -1;
	}
	if (cap_set_proc(caps) < 0) {
		perror("GhostBox: cap_set_proc failed");
		cap_free(caps);
		return -1;
	}
	cap_free(caps);
	
	return 0;
}

int apply_landlock_mac(void) {
	int abi = syscall(SYS_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION);
	if (abi < 0) {
		perror("[-] GhostBox: Landlock ABI not supported or initialization failed");
		blockage_killswitch();
		return -1;
	}
	
	struct ghostbox_landlock_ruleset_attr ruleset_attr = {0};
	
	// Base ABI 1 access flags
	__u64 access_fs_abi1 = LANDLOCK_ACCESS_FS_EXECUTE |
	LANDLOCK_ACCESS_FS_WRITE_FILE |
	LANDLOCK_ACCESS_FS_READ_FILE |
	LANDLOCK_ACCESS_FS_READ_DIR |
	LANDLOCK_ACCESS_FS_REMOVE_DIR |
	LANDLOCK_ACCESS_FS_REMOVE_FILE |
	LANDLOCK_ACCESS_FS_MAKE_CHAR |
	LANDLOCK_ACCESS_FS_MAKE_DIR |
	LANDLOCK_ACCESS_FS_MAKE_REG |
	LANDLOCK_ACCESS_FS_MAKE_SOCK |
	LANDLOCK_ACCESS_FS_MAKE_FIFO |
	LANDLOCK_ACCESS_FS_MAKE_BLOCK |
	LANDLOCK_ACCESS_FS_MAKE_SYM;
	
	ruleset_attr.handled_access_fs = access_fs_abi1;
	
	if (abi >= 2) {
		ruleset_attr.handled_access_fs |= LANDLOCK_ACCESS_FS_REFER;
	}
	if (abi >= 3) {
		ruleset_attr.handled_access_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
	}
	if (abi >= 4) {
		ruleset_attr.handled_access_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP;
	}
	if (abi >= 5) {
		ruleset_attr.handled_access_fs |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
	}
	
	int ruleset_fd = syscall(SYS_landlock_create_ruleset, &ruleset_attr, sizeof(ruleset_attr), 0);
	if (ruleset_fd < 0) {
		perror("[-] GhostBox: landlock_create_ruleset failed");
		blockage_killswitch();
		return -1;
	}
	
	// 1. Read and execute access for trusted system paths
	static const char * const ro_exec_paths[] = {
		"/usr", "/bin", "/lib", "/lib64", "/opt", "/snap", "/var", "/etc", NULL
	};
	
	__u64 ro_exec_access = LANDLOCK_ACCESS_FS_READ_FILE |
	LANDLOCK_ACCESS_FS_READ_DIR |
	LANDLOCK_ACCESS_FS_EXECUTE;
	
	for (int i = 0; ro_exec_paths[i] != NULL; i++) {
		int path_fd = open(ro_exec_paths[i], O_PATH | O_CLOEXEC);
		if (path_fd >= 0) {
			struct ghostbox_landlock_path_beneath_attr path_beneath = {
				.allowed_access = ro_exec_access,
				.parent_fd = path_fd,
			};
			if (syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0) < 0) {
				close(path_fd);
				close(ruleset_fd);
				perror("[-] GhostBox: landlock_add_rule failed for ro_exec_paths");
				blockage_killswitch();
				return -1;
			}
			close(path_fd);
		}
	}
	
	// 2. Full access for isolated RAM workspace (/dev/shm/ghostbox_home, /dev/shm/ghostbox_root, /dev/shm/ghostbox_pivot, /dev/shm/ghostbox_wayland and /dev/shm)
	static const char * const rw_workspace_paths[] = {
		"/dev/shm/ghostbox_home", "/dev/shm/ghostbox_root", "/dev/shm/ghostbox_pivot", "/dev/shm/ghostbox_wayland", "/dev/shm", NULL
	};
	
	__u64 rw_workspace_access = ruleset_attr.handled_access_fs;
	
	for (int i = 0; rw_workspace_paths[i] != NULL; i++) {
		int path_fd = open(rw_workspace_paths[i], O_PATH | O_CLOEXEC);
		if (path_fd >= 0) {
			struct ghostbox_landlock_path_beneath_attr path_beneath = {
				.allowed_access = rw_workspace_access,
				.parent_fd = path_fd,
			};
			if (syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0) < 0) {
				close(path_fd);
				close(ruleset_fd);
				perror("[-] GhostBox: landlock_add_rule failed for rw_workspace_paths");
				blockage_killswitch();
				return -1;
			}
			close(path_fd);
		}
	}
	
	// 3. Read-only access for /proc
	int proc_fd = open("/proc", O_PATH | O_CLOEXEC);
	if (proc_fd >= 0) {
		struct ghostbox_landlock_path_beneath_attr path_beneath = {
			.allowed_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR,
			.parent_fd = proc_fd,
		};
		if (syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0) < 0) {
			close(proc_fd);
			close(ruleset_fd);
			perror("[-] GhostBox: landlock_add_rule failed for /proc");
			blockage_killswitch();
			return -1;
		}
		close(proc_fd);
	}
	
	// 4. Read/Write access for essential character devices
	static const char * const dev_nodes[] = {
		"/dev/null", "/dev/zero", "/dev/full", "/dev/random", "/dev/urandom", "/dev/pts", NULL
	};
	
	__u64 dev_access = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE;
	
	for (int i = 0; dev_nodes[i] != NULL; i++) {
		int path_fd = open(dev_nodes[i], O_PATH | O_CLOEXEC);
		if (path_fd >= 0) {
			struct ghostbox_landlock_path_beneath_attr path_beneath = {
				.allowed_access = dev_access,
				.parent_fd = path_fd,
			};
			if (syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, &path_beneath, 0) < 0) {
				close(path_fd);
				close(ruleset_fd);
				perror("[-] GhostBox: landlock_add_rule failed for dev_nodes");
				blockage_killswitch();
				return -1;
			}
			close(path_fd);
		}
	}
	
	// 5. Landlock network rules restricted specifically to outgoing web, DNS, and proxy ports (blocks local port binding)
	if (abi >= 4) {
		static const uint16_t allowed_connect_ports[] = {
			53, 80, 443, 853, 1080, 3128, 8000, 8080, 8081, 8443, 8888, 9001, 9050, 9051, 9150
		};
		for (size_t p = 0; p < sizeof(allowed_connect_ports) / sizeof(allowed_connect_ports[0]); p++) {
			struct ghostbox_landlock_net_port_attr net_port = {
				.allowed_access = LANDLOCK_ACCESS_NET_CONNECT_TCP,
				.port = allowed_connect_ports[p],
			};
			syscall(SYS_landlock_add_rule, ruleset_fd, LANDLOCK_RULE_NET_PORT, &net_port, 0);
		}
	}
	
	// Ensure NO_NEW_PRIVS is set prior to restricting self
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		perror("[-] GhostBox: Failed to set NO_NEW_PRIVS for Landlock");
		close(ruleset_fd);
		blockage_killswitch();
		return -1;
	}
	
	if (syscall(SYS_landlock_restrict_self, ruleset_fd, 0) < 0) {
		perror("[-] GhostBox: Failed to enforce Landlock restrict_self");
		close(ruleset_fd);
		blockage_killswitch();
		return -1;
	}
	
	close(ruleset_fd);
	printf("[*] GhostBox: Landlock MAC successfully engaged (ABI version %d).\n", abi);
	return 0;
}

int apply_seccomp_filter(void) {
	if (prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) < 0) {
		perror("GhostBox: Failed to disable core dumps");
		return -1;
	}
	
	if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0) {
		perror("GhostBox: Failed to set NO_NEW_PRIVS");
		return -1;
	}
	
	scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_KILL_PROCESS);
	if (ctx == NULL) {
		perror("GhostBox: seccomp_init failed");
		blockage_killswitch();
		return -1;
	}
	
	int rc = 0;
	
	// --- HIGH-RISK SYSCALL RESTRICTIONS (GRACEFUL FALLBACKS) ---
	
	// Intercept ioctl with TIOCSTI (0x5412) to block terminal keystroke injection attacks
	if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioctl), 1,
		SCMP_CMP(1, SCMP_CMP_EQ, TIOCSTI)) < 0) rc = -1;
	
	// Intercept socket creation arguments to block AF_NETLINK sockets with NETLINK_SOCK_DIAG
	if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(socket), 2,
		SCMP_CMP(0, SCMP_CMP_EQ, AF_NETLINK),
						 SCMP_CMP(2, SCMP_CMP_EQ, NETLINK_SOCK_DIAG)) < 0) rc = -1;
						 
						 // Deny direct hardware port mapping and kernel ring-buffer access
						 if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(iopl), 0) < 0) rc = -1;
						 if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ioperm), 0) < 0) rc = -1;
						 if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(syslog), 0) < 0) rc = -1;
						 
						 // Force glibc clone3 to fall back to legacy clone()
						 if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(ENOSYS), SCMP_SYS(clone3), 0) < 0) rc = -1;
						 
						 // Deny nested namespace manipulation cleanly
						 if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(unshare), 0) < 0) rc = -1;
						 
						 // Deny execution domain switching, process tracing, memory inspection, and kernel modifications
						 if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(personality), 0) < 0) rc = -1;
						 if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(ptrace), 0) < 0) rc = -1;
						 if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kcmp), 0) < 0) rc = -1;
						 if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(process_vm_readv), 0) < 0) rc = -1;
						 if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(process_vm_writev), 0) < 0) rc = -1;
						 if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(init_module), 0) < 0) rc = -1;
						 if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(finit_module), 0) < 0) rc = -1;
						 if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(delete_module), 0) < 0) rc = -1;
						 if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kexec_load), 0) < 0) rc = -1;
						 if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(kexec_file_load), 0) < 0) rc = -1;
						 
						 // Filter clone flags: block namespace instantiation while allowing thread creation
						 const unsigned long ns_clone_flags[] = {
							 CLONE_NEWUSER, CLONE_NEWNET, CLONE_NEWNS,
							 CLONE_NEWPID,  CLONE_NEWIPC, CLONE_NEWUTS, CLONE_NEWCGROUP
						 };
						 for (size_t i = 0; i < sizeof(ns_clone_flags) / sizeof(ns_clone_flags[0]); i++) {
							 if (seccomp_rule_add(ctx, SCMP_ACT_ERRNO(EPERM), SCMP_SYS(clone), 1,
								 SCMP_CMP(0, SCMP_CMP_MASKED_EQ, ns_clone_flags[i], ns_clone_flags[i])) < 0) {
								 rc = -1;
							 break;
								 }
						 }
						 
						 // --- STANDARD DESKTOP APPLICATION ALLOWLIST ---
						 
						 const int syscalls[] = {
							 SCMP_SYS(read), SCMP_SYS(write), SCMP_SYS(open), SCMP_SYS(openat), SCMP_SYS(close),
							 SCMP_SYS(stat), SCMP_SYS(fstat), SCMP_SYS(lstat), SCMP_SYS(newfstatat), SCMP_SYS(statx),
							 SCMP_SYS(lseek), SCMP_SYS(access), SCMP_SYS(faccessat), SCMP_SYS(unlink), SCMP_SYS(unlinkat),
							 SCMP_SYS(rmdir), SCMP_SYS(pread64), SCMP_SYS(pwrite64), SCMP_SYS(readv), SCMP_SYS(writev),
							 SCMP_SYS(readlink), SCMP_SYS(readlinkat), SCMP_SYS(getdents), SCMP_SYS(getdents64),
							 SCMP_SYS(statfs), SCMP_SYS(fstatfs), SCMP_SYS(mkdirat), SCMP_SYS(rename), SCMP_SYS(renameat),
							 SCMP_SYS(ftruncate), SCMP_SYS(flock), SCMP_SYS(fchmod), SCMP_SYS(fchown), SCMP_SYS(fchmodat),
							 SCMP_SYS(fchownat), SCMP_SYS(fadvise64), SCMP_SYS(poll), SCMP_SYS(select), SCMP_SYS(ppoll),
							 SCMP_SYS(pselect6), SCMP_SYS(pipe), SCMP_SYS(pipe2), SCMP_SYS(dup), SCMP_SYS(dup2),
							 SCMP_SYS(dup3), SCMP_SYS(fcntl), SCMP_SYS(ioctl), SCMP_SYS(getcwd), SCMP_SYS(chdir),
							 SCMP_SYS(clone), SCMP_SYS(fork), SCMP_SYS(vfork), SCMP_SYS(execve),
							 SCMP_SYS(exit), SCMP_SYS(exit_group), SCMP_SYS(wait4), SCMP_SYS(kill), SCMP_SYS(tkill),
							 SCMP_SYS(tgkill), SCMP_SYS(socket), SCMP_SYS(connect), SCMP_SYS(bind), SCMP_SYS(accept),
							 SCMP_SYS(accept4), SCMP_SYS(getsockname), SCMP_SYS(getpeername), SCMP_SYS(getsockopt),
							 SCMP_SYS(setsockopt), SCMP_SYS(sendto), SCMP_SYS(recvfrom), SCMP_SYS(sendmsg),
							 SCMP_SYS(recvmsg), SCMP_SYS(socketpair), SCMP_SYS(shutdown), SCMP_SYS(getuid),
							 SCMP_SYS(geteuid), SCMP_SYS(getgid), SCMP_SYS(getegid), SCMP_SYS(getpid), SCMP_SYS(getppid),
							 SCMP_SYS(gettid), SCMP_SYS(getxattr), SCMP_SYS(lgetxattr), SCMP_SYS(fgetxattr),
							 SCMP_SYS(listxattr), SCMP_SYS(flistxattr), SCMP_SYS(llistxattr), SCMP_SYS(capget), SCMP_SYS(capset),
							 SCMP_SYS(setresuid), SCMP_SYS(setresgid), SCMP_SYS(shmget), SCMP_SYS(shmat), SCMP_SYS(shmdt), SCMP_SYS(shmctl), SCMP_SYS(mmap),
							 SCMP_SYS(mprotect), SCMP_SYS(munmap), SCMP_SYS(mremap), SCMP_SYS(madvise), SCMP_SYS(brk),
							 SCMP_SYS(rt_sigaction), SCMP_SYS(rt_sigprocmask), SCMP_SYS(rt_sigreturn), SCMP_SYS(futex),
							 SCMP_SYS(set_tid_address), SCMP_SYS(set_robust_list), SCMP_SYS(arch_prctl), SCMP_SYS(prctl),
							 SCMP_SYS(prlimit64), SCMP_SYS(getrlimit), SCMP_SYS(gettimeofday), SCMP_SYS(umask),
							 SCMP_SYS(getrandom), SCMP_SYS(rseq), SCMP_SYS(clock_gettime), SCMP_SYS(sched_getaffinity),
							 SCMP_SYS(sched_setaffinity), SCMP_SYS(sched_yield), SCMP_SYS(getgroups), SCMP_SYS(getresuid),
							 SCMP_SYS(getresgid), SCMP_SYS(sysinfo), SCMP_SYS(getrusage), SCMP_SYS(times), SCMP_SYS(getcpu),
							 SCMP_SYS(getpriority), SCMP_SYS(setpriority), SCMP_SYS(uname), SCMP_SYS(epoll_create1),
							 SCMP_SYS(epoll_ctl), SCMP_SYS(epoll_wait), SCMP_SYS(epoll_pwait), SCMP_SYS(eventfd2),
							 SCMP_SYS(signalfd4), SCMP_SYS(timerfd_create), SCMP_SYS(timerfd_settime), SCMP_SYS(fsync),
							 SCMP_SYS(fdatasync), SCMP_SYS(restart_syscall), SCMP_SYS(inotify_init), SCMP_SYS(inotify_init1),
							 SCMP_SYS(inotify_add_watch), SCMP_SYS(inotify_rm_watch), SCMP_SYS(clock_nanosleep),
							 SCMP_SYS(sched_setscheduler), SCMP_SYS(sched_getscheduler), SCMP_SYS(memfd_create),
							 SCMP_SYS(seccomp), SCMP_SYS(listen), SCMP_SYS(sendmmsg),
							 SCMP_SYS(recvmmsg), SCMP_SYS(preadv), SCMP_SYS(pwritev), SCMP_SYS(preadv2), SCMP_SYS(pwritev2),
							 SCMP_SYS(fallocate), SCMP_SYS(renameat2), SCMP_SYS(mlock), SCMP_SYS(munlock), SCMP_SYS(mbind),
							 SCMP_SYS(set_mempolicy), SCMP_SYS(get_mempolicy), SCMP_SYS(clock_getres), SCMP_SYS(waitid),
							 SCMP_SYS(setrlimit), SCMP_SYS(rt_sigpending), SCMP_SYS(rt_sigtimedwait), SCMP_SYS(rt_sigsuspend),
							 SCMP_SYS(timerfd_gettime), SCMP_SYS(symlink), SCMP_SYS(symlinkat), SCMP_SYS(link),
							 SCMP_SYS(linkat), SCMP_SYS(mkdir), SCMP_SYS(chmod), SCMP_SYS(chown), SCMP_SYS(lchown),
							 SCMP_SYS(sched_getattr), SCMP_SYS(sched_setattr), SCMP_SYS(epoll_create), SCMP_SYS(eventfd),
							 SCMP_SYS(signalfd), SCMP_SYS(sendfile), SCMP_SYS(msync), SCMP_SYS(mincore), SCMP_SYS(mlockall),
							 SCMP_SYS(munlockall), SCMP_SYS(getpgrp), SCMP_SYS(getsid), SCMP_SYS(sched_rr_get_interval),
							 SCMP_SYS(membarrier), SCMP_SYS(close_range), SCMP_SYS(copy_file_range), SCMP_SYS(splice),
							 SCMP_SYS(tee), SCMP_SYS(vmsplice), SCMP_SYS(readahead), SCMP_SYS(sigaltstack), SCMP_SYS(setsid),
							 SCMP_SYS(sched_getparam), SCMP_SYS(sched_get_priority_min), SCMP_SYS(sched_get_priority_max),
							 SCMP_SYS(faccessat2), SCMP_SYS(semget), SCMP_SYS(semop), SCMP_SYS(semctl),
							 SCMP_SYS(msgget), SCMP_SYS(msgsnd), SCMP_SYS(msgrcv), SCMP_SYS(truncate), SCMP_SYS(fchdir),
							 SCMP_SYS(utimes), SCMP_SYS(utimensat), SCMP_SYS(futimesat), SCMP_SYS(clock_settime),
							 SCMP_SYS(timer_create), SCMP_SYS(timer_settime), SCMP_SYS(timer_gettime), SCMP_SYS(timer_getoverrun),
							 SCMP_SYS(timer_delete), SCMP_SYS(alarm), SCMP_SYS(setitimer), SCMP_SYS(getitimer),
							 SCMP_SYS(setpgid), SCMP_SYS(setgroups), SCMP_SYS(get_robust_list), SCMP_SYS(io_setup),
							 SCMP_SYS(io_destroy), SCMP_SYS(io_submit), SCMP_SYS(io_cancel), SCMP_SYS(io_getevents),
							 SCMP_SYS(setxattr), SCMP_SYS(lsetxattr), SCMP_SYS(fsetxattr),
							 SCMP_SYS(removexattr), SCMP_SYS(nanosleep), SCMP_SYS(pkey_alloc), SCMP_SYS(pkey_free),
							 SCMP_SYS(pkey_mprotect), SCMP_SYS(pidfd_open), SCMP_SYS(pidfd_send_signal), SCMP_SYS(pidfd_getfd),
							 SCMP_SYS(sync), SCMP_SYS(syncfs), SCMP_SYS(rt_tgsigqueueinfo),
							 SCMP_SYS(rt_sigqueueinfo), SCMP_SYS(name_to_handle_at), SCMP_SYS(open_by_handle_at),
							 SCMP_SYS(mq_open), SCMP_SYS(mq_unlink), SCMP_SYS(mq_timedsend), SCMP_SYS(mq_timedreceive),
							 SCMP_SYS(mq_notify), SCMP_SYS(mq_getsetattr), SCMP_SYS(msgctl), SCMP_SYS(get_thread_area),
							 SCMP_SYS(set_thread_area),
							 SCMP_SYS(quotactl), SCMP_SYS(ioprio_get), SCMP_SYS(ioprio_set), SCMP_SYS(setfsuid),
							 SCMP_SYS(setfsgid), SCMP_SYS(pivot_root), SCMP_SYS(umount2)
						 };
						 
						 if (rc == 0) {
							 for (size_t i = 0; i < sizeof(syscalls) / sizeof(syscalls[0]); i++) {
								 if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscalls[i], 0) < 0) {
									 rc = -1;
									 break;
								 }
							 }
						 }
						 
						 if (rc == 0) {
							 rc = seccomp_load(ctx);
						 }
						 
						 seccomp_release(ctx);
						 
						 if (rc < 0) {
							 perror("GhostBox: Failed to apply seccomp filter via libseccomp");
							 blockage_killswitch();
							 return -1;
						 }
						 
						 return 0;
}
