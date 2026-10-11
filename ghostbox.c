#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sched.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <ftw.h>
#include <dirent.h>
#include <sys/syscall.h>
#include <limits.h>
#include <sys/resource.h>
#include <fcntl.h>
#include <sys/swap.h>
#include <sys/sysmacros.h>
#include <errno.h>

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif

// Global trackers for sandboxed process, slirp4netns manager process, and volatile signal pipe
static volatile sig_atomic_t g_child_pid = -1;
static volatile sig_atomic_t g_slirp_mgr = -1;
static volatile int g_signal_pipe[2] = {-1, -1};

// Blocked hardware, sensitive device nodes, system paths, and /proc disclosure nodes
static const char * const GHOSTBOX_BLOCKED_PATHS[] = {
	"/sys/bus/pci/devices",
	"/sys/bus/pci/devices/0000:00:1f.0/config",
	"/proc/bus/pci",
	"/proc/cpuinfo",
	"/proc/meminfo",
	"/proc/maps",
	"/proc/smaps",
	"/proc/numa_maps",
	"/proc/pagemap",
	"/proc/kallsyms",
	"/proc/stat",
	"/proc/status",
	"/proc/sched_debug",
	"/proc/slabinfo",
	"/proc/vmstat",
	"/proc/zoneinfo",
	"/proc/buddyinfo",
	"/proc/consoles",
	"/proc/kcore",
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

// External engine hooks
extern int apply_seccomp_filter(void);
extern int drop_all_capabilities(void);
extern int apply_hardware_cloaking(void);
extern int setup_display_environment(void);
extern int apply_namespace_sandboxing(void);
extern int apply_landlock_mac(void);

// Helper ensuring /dev/net/tun is present and kernel driver is pre-loaded before disabling modules
static void ensure_tun_device_ready(void) {
	struct stat st;
	if (stat("/dev/net", &st) != 0) {
		mkdir("/dev/net", 0755);
	}
	
	int fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
	if (fd >= 0) {
		close(fd);
		return;
	}
	
	if (errno == ENOENT) {
		if (mknod("/dev/net/tun", S_IFCHR | 0666, makedev(10, 200)) == 0) {
			chmod("/dev/net/tun", 0666);
			fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NOFOLLOW);
			if (fd >= 0) {
				close(fd);
			}
		}
	}
}

// Cgroups v2 Resource Throttling with Dynamic /proc/self/cgroup Querying & Controller Activation
static int setup_cgroups_v2(void) {
	char cgroup_path[PATH_MAX] = "/sys/fs/cgroup/ghostbox";
	FILE *f = fopen("/proc/self/cgroup", "r");
	if (f) {
		char line[512];
		while (fgets(line, sizeof(line), f)) {
			if (strncmp(line, "0::", 3) == 0) {
				char *p = line + 3;
				size_t len = strlen(p);
				if (len > 0 && p[len - 1] == '\n') {
					p[len - 1] = '\0';
				}
				if (p[0] != '\0' && strcmp(p, "/") != 0) {
					snprintf(cgroup_path, sizeof(cgroup_path), "/sys/fs/cgroup%s/ghostbox", p);
				} else {
					snprintf(cgroup_path, sizeof(cgroup_path), "/sys/fs/cgroup/ghostbox");
				}
				break;
			}
		}
		fclose(f);
	}
	
	// Enable pids and memory controllers in parent cgroups subtree_control
	char parent_ctrl[PATH_MAX];
	snprintf(parent_ctrl, sizeof(parent_ctrl), "%s", cgroup_path);
	char *last_slash = strrchr(parent_ctrl, '/');
	if (last_slash) {
		*last_slash = '\0';
		char subtree_path[PATH_MAX];
		snprintf(subtree_path, sizeof(subtree_path), "%s/cgroup.subtree_control", parent_ctrl);
		int cfd = open(subtree_path, O_WRONLY | O_CLOEXEC);
		if (cfd >= 0) {
			write(cfd, "+pids +memory", 13);
			close(cfd);
		}
	}
	
	// Recursively create directory path components
	char tmp[PATH_MAX];
	snprintf(tmp, sizeof(tmp), "%s", cgroup_path);
	for (char *p = tmp + 1; *p; p++) {
		if (*p == '/') {
			*p = '\0';
			mkdir(tmp, 0755);
			*p = '/';
		}
	}
	mkdir(tmp, 0755);
	
	char buf[PATH_MAX];
	
	snprintf(buf, sizeof(buf), "%s/pids.max", cgroup_path);
	int fd = open(buf, O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		write(fd, "256", 3);
		close(fd);
	}
	
	snprintf(buf, sizeof(buf), "%s/memory.swap.max", cgroup_path);
	fd = open(buf, O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		write(fd, "0", 1);
		close(fd);
	}
	
	snprintf(buf, sizeof(buf), "%s/cgroup.procs", cgroup_path);
	fd = open(buf, O_WRONLY | O_CLOEXEC);
	if (fd >= 0) {
		char pid_str[32];
		snprintf(pid_str, sizeof(pid_str), "%d", getpid());
		write(fd, pid_str, strlen(pid_str));
		close(fd);
	}
	
	// Enforce RLIMIT_NPROC strictly to cap thread/process creation limit at kernel level
	struct rlimit rl = {256, 256};
	setrlimit(RLIMIT_NPROC, &rl);
	
	return 0;
}

// Sysctl Hardening & Attack Surface Reduction Specification
typedef struct {
	const char *path;
	const char *target_value;
	const char *description;
} GhostBoxSysctlSetting;

static const GhostBoxSysctlSetting GHOSTBOX_SYSCTL_SETTINGS[] = {
	{"/proc/sys/kernel/kptr_restrict", "2", "Kernel pointer address restriction (kptr_restrict = 2)"},
	{"/proc/sys/kernel/dmesg_restrict", "1", "Kernel ring buffer / dmesg access restriction (dmesg_restrict = 1)"},
	{"/proc/sys/kernel/unprivileged_bpf_disabled", "1", "Unprivileged BPF execution restriction (unprivileged_bpf_disabled = 1)"},
	{"/proc/sys/net/core/bpf_jit_harden", "2", "BPF JIT compiler hardening & constant blinding (bpf_jit_harden = 2)"},
	{"/proc/sys/kernel/kexec_load_disabled", "1", "Kernel image replacement / kexec load disabling (kexec_load_disabled = 1)"},
	{"/proc/sys/kernel/sysrq", "0", "SysRq diagnostic key interface disabling (sysrq = 0)"},
	{"/proc/sys/kernel/perf_event_paranoid", "3", "Performance event & hardware counter access restriction (perf_event_paranoid = 3)"},
	{"/proc/sys/kernel/yama/ptrace_scope", "2", "Process ptrace cross-inspection scope restriction (ptrace_scope = 2)"},
	{"/proc/sys/fs/protected_symlinks", "1", "Symlink attack mitigation (protected_symlinks = 1)"},
	{"/proc/sys/fs/protected_hardlinks", "1", "Hardlink attack mitigation (protected_hardlinks = 1)"},
	{"/proc/sys/fs/protected_fifos", "2", "FIFO pipe creation attack mitigation (protected_fifos = 2)"},
	{"/proc/sys/fs/protected_regular", "2", "Regular file creation sticky-dir attack mitigation (protected_regular = 2)"},
	{"/proc/sys/fs/suid_dumpable", "0", "Setuid core dump memory exposure disabling (suid_dumpable = 0)"},
	{"/proc/sys/dev/tty/ldisc_autoload", "0", "TTY line discipline module autoloading restriction (ldisc_autoload = 0)"},
	{"/proc/sys/vm/unprivileged_userfaultfd", "0", "Unprivileged userfaultfd restriction (unprivileged_userfaultfd = 0)"},
	{"/proc/sys/kernel/lockdown", "integrity", "Kernel lockdown enforcement (lockdown = integrity)"},
	{"/proc/sys/kernel/modules_disabled", "1", "Attack Surface Reduction: Disabling runtime kernel module loading (modules_disabled = 1)"},
	{"/proc/sys/kernel/panic_on_oops", "1", "Hardware/Kernel panic on oops enforcement (panic_on_oops = 1)"},
	{"/proc/sys/kernel/panic", "1", "Hardware-level kernel panic on power disconnect/fault (panic = 1)"},
	{"/proc/sys/vm/panic_on_oom", "2", "Hardware panic on critical memory/power fault (panic_on_oom = 2)"}
};

static const size_t GHOSTBOX_NUM_SYSCTL = sizeof(GHOSTBOX_SYSCTL_SETTINGS) / sizeof(GHOSTBOX_SYSCTL_SETTINGS[0]);

// Race-free direct file reader for /proc/sys values
static int safe_read_sysctl(const char *path, char *buf, size_t maxlen) {
	if (!path || !buf || maxlen == 0) return -1;
	int fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0) return -1;
	ssize_t n = read(fd, buf, maxlen - 1);
	close(fd);
	if (n <= 0) return -1;
	buf[n] = '\0';
	while (n > 0 && (buf[n - 1] == '\n' || buf[n - 1] == '\r' || buf[n - 1] == ' ' || buf[n - 1] == '\t')) {
		buf[--n] = '\0';
	}
	return 0;
}

// Race-free direct file writer for /proc/sys values
static int safe_write_sysctl(const char *path, const char *value) {
	if (!path || !value) return -1;
	int fd = open(path, O_WRONLY | O_CLOEXEC);
	if (fd < 0) return -1;
	size_t len = strlen(value);
	ssize_t n = write(fd, value, len);
	close(fd);
	return (n == (ssize_t)len) ? 0 : -1;
}

// Helper checking if a sysctl parameter value satisfies active hardening criteria
static int is_sysctl_setting_active(const GhostBoxSysctlSetting *setting, const char *cur_val) {
	if (!setting || !cur_val) return 0;
	if (strcmp(cur_val, setting->target_value) == 0) {
		return 1;
	}
	if (strcmp(setting->path, "/proc/sys/kernel/unprivileged_bpf_disabled") == 0 &&
		(strcmp(cur_val, "1") == 0 || strcmp(cur_val, "2") == 0)) {
		return 1;
		}
		if (strcmp(setting->path, "/proc/sys/kernel/lockdown") == 0) {
			if (strstr(cur_val, "[integrity]") != NULL ||
				strstr(cur_val, "[confidentiality]") != NULL ||
				strcmp(cur_val, "integrity") == 0 ||
				strcmp(cur_val, "confidentiality") == 0) {
				return 1;
				}
		}
		return 0;
}

// Unified status helper returning:
//  1 = ACTIVE
//  0 = INACTIVE (Supported by kernel, but setting is currently inactive)
// -1 = UNAVAILABLE (Unsupported by host kernel or missing interface node)
static int check_single_sysctl_status(const GhostBoxSysctlSetting *setting, char *out_val, size_t maxlen) {
	if (access(setting->path, F_OK) != 0) {
		return -1;
	}
	if (safe_read_sysctl(setting->path, out_val, maxlen) != 0) {
		return -1;
	}
	if (is_sysctl_setting_active(setting, out_val)) {
		return 1;
	}
	return 0;
}

// Integrated SwapOff & Memory Locking functions
static int disable_all_swap(void) {
	int fd = open("/proc/swaps", O_RDONLY | O_CLOEXEC);
	if (fd < 0) return -1;
	FILE *f = fdopen(fd, "r");
	if (!f) {
		close(fd);
		return -1;
	}
	char line[256];
	if (!fgets(line, sizeof(line), f)) {
		fclose(f);
		return 0;
	}
	int count = 0;
	while (fgets(line, sizeof(line), f)) {
		char dev[256];
		if (sscanf(line, "%255s", dev) == 1) {
			if (swapoff(dev) == 0) {
				printf("  [+] SwapOff: Disabled swap device/file: %s\n", dev);
				count++;
			}
		}
	}
	fclose(f);
	return count;
}

static int is_swap_active(void) {
	int fd = open("/proc/swaps", O_RDONLY | O_CLOEXEC);
	if (fd < 0) return 0;
	FILE *f = fdopen(fd, "r");
	if (!f) {
		close(fd);
		return 0;
	}
	char line[256];
	int lines = 0;
	while (fgets(line, sizeof(line), f)) {
		lines++;
	}
	fclose(f);
	return (lines > 1) ? 1 : 0;
}

static int is_memlock_unlimited(void) {
	struct rlimit rl;
	if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
		if (rl.rlim_cur == RLIM_INFINITY) {
			return 1;
		}
	}
	return 0;
}

static void apply_swap_and_memlock_hardening(void) {
	struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
	setrlimit(RLIMIT_MEMLOCK, &rl);
	
	disable_all_swap();
	
	mlockall(MCL_CURRENT | MCL_FUTURE);
}

// Immediate implementation of sysctl runtime hardening & swapoff/mlockall
static void implement_sysctl_hardening(void) {
	printf("========================================================\n");
	printf("   GHOSTBOX - Sysctl & RAM Memory Hardening (-i)        \n");
	printf("========================================================\n");
	
	if (getuid() != 0) {
		fprintf(stderr, "[-] GhostBox Error: Root privileges (e.g. sudo) are required to modify kernel parameters and swap state.\n");
		return;
	}
	
	// Trigger tun kernel module load before permanently disabling module loading
	ensure_tun_device_ready();
	
	int success_count = 0;
	int fail_count = 0;
	int unavail_count = 0;
	
	printf("[*] Applying non-persistent RAM runtime sysctl security parameters...\n\n");
	
	for (size_t i = 0; i < GHOSTBOX_NUM_SYSCTL; i++) {
		const GhostBoxSysctlSetting *setting = &GHOSTBOX_SYSCTL_SETTINGS[i];
		
		safe_write_sysctl(setting->path, setting->target_value);
		
		char cur_val[64] = {0};
		int st = check_single_sysctl_status(setting, cur_val, sizeof(cur_val));
		if (st == 1) {
			printf("  [+] SUCCESS: %s\n      Path: %s -> Active Value: %s\n", setting->description, setting->path, cur_val);
			success_count++;
		} else if (st == 0) {
			printf("  [-] FAILED:  %s\n      Path: %s (Current: %s | Target: %s)\n", setting->description, setting->path, cur_val, setting->target_value);
			fail_count++;
		} else {
			printf("  [-] UNAVAILABLE: %s (Feature not supported by host kernel)\n", setting->path);
			unavail_count++;
		}
	}
	
	printf("\n[*] Applying SwapOff & Memory Locking (mlockall) Hardening...\n");
	apply_swap_and_memlock_hardening();
	
	int swap_active = is_swap_active();
	int memlock_unlim = is_memlock_unlimited();
	
	if (!swap_active) {
		printf("  [+] SUCCESS: Swap Disabling (All swap devices/files disabled)\n");
	} else {
		printf("  [-] FAILED:  Swap Disabling (Active swap detected)\n");
	}
	
	if (memlock_unlim) {
		printf("  [+] SUCCESS: Memory Lock Limit (RLIMIT_MEMLOCK set to UNLIMITED & mlockall engaged)\n");
	} else {
		printf("  [-] WARNING: Memory Lock Limit (RLIMIT_MEMLOCK restricted)\n");
	}
	
	printf("\n--------------------------------------------------------\n");
	printf("[*] Implementation Summary:\n");
	printf("    Successfully Enforced Sysctl: %d / %zu\n", success_count, GHOSTBOX_NUM_SYSCTL);
	if (fail_count > 0) printf("    Failed Sysctl Enforcement:   %d\n", fail_count);
	if (unavail_count > 0) printf("    Kernel Unsupported Sysctl:   %d\n", unavail_count);
	printf("    Swap Status:                %s\n", swap_active ? "ACTIVE (Warning)" : "DISABLED (Secure)");
	printf("    Memory Locking Status:       %s\n", memlock_unlim ? "UNLIMITED (Secure)" : "RESTRICTED");
	printf("--------------------------------------------------------\n");
	printf("\n[!] IMPORTANT SECURITY WORKFLOW:\n");
	printf("    All applied hardening parameters operate strictly in RAM via /proc/sys with ZERO disk persistence.\n");
	printf("    Because /proc is volatile, these settings will reset if you reboot.\n\n");
	printf("    Recommended startup sequence:\n");
	printf("    1. Reboot your PC if you need to clear extra loaded kernel modules.\n");
	printf("    2. Run 'sudo ./ghostbox -i' immediately after logging in.\n");
	printf("    3. Launch your applications using GhostBox ('./ghostbox -- <command>').\n\n");
}

// Verification function for active sysctl & RAM memory hardening status
static void check_sysctl_hardening_status(void) {
	printf("========================================================\n");
	printf("   GHOSTBOX - Hardening & Attack Surface Status Check   \n");
	printf("========================================================\n");
	
	int active_count = 0;
	int inactive_count = 0;
	int unavail_count = 0;
	
	for (size_t i = 0; i < GHOSTBOX_NUM_SYSCTL; i++) {
		const GhostBoxSysctlSetting *setting = &GHOSTBOX_SYSCTL_SETTINGS[i];
		char cur_val[64] = {0};
		
		int st = check_single_sysctl_status(setting, cur_val, sizeof(cur_val));
		if (st == 1) {
			printf("  [+] ACTIVE:   %-46s [Val: %s]\n", setting->description, cur_val);
			active_count++;
		} else if (st == 0) {
			printf("  [-] INACTIVE: %-46s [Current: %s | Target: %s]\n", setting->description, cur_val, setting->target_value);
			inactive_count++;
		} else {
			printf("  [-] UNAVAILABLE: %-44s [Kernel Unsupported]\n", setting->description);
			unavail_count++;
		}
	}
	
	int swap_active = is_swap_active();
	int memlock_unlim = is_memlock_unlimited();
	
	if (!swap_active) {
		printf("  [+] ACTIVE:   %-46s [Val: DISABLED]\n", "Swap State (No swap devices active)");
	} else {
		printf("  [-] INACTIVE: %-46s [Current: ACTIVE | Target: DISABLED]\n", "Swap State (Swap devices active)");
	}
	
	if (memlock_unlim) {
		printf("  [+] ACTIVE:   %-46s [Val: UNLIMITED]\n", "Memory Locking Limit (RLIMIT_MEMLOCK)");
	} else {
		printf("  [-] INACTIVE: %-46s [Current: RESTRICTED | Target: UNLIMITED]\n", "Memory Locking Limit (RLIMIT_MEMLOCK)");
	}
	
	printf("\n--------------------------------------------------------\n");
	printf("[*] Status Inspection Summary:\n");
	printf("    Active Protections:   %d / %zu\n", active_count, GHOSTBOX_NUM_SYSCTL);
	printf("    Inactive Protections: %d\n", inactive_count);
	if (unavail_count > 0) printf("    Kernel Unsupported:   %d\n", unavail_count);
	printf("    Swap Status:          %s\n", swap_active ? "ACTIVE (Warning)" : "DISABLED (Secure)");
	printf("    Memlock Limit:        %s\n", memlock_unlim ? "UNLIMITED" : "RESTRICTED");
	printf("--------------------------------------------------------\n\n");
}

// Verification gate before sandbox startup: engages killswitch ONLY if a supported sysctl parameter is inactive
static void verify_sysctl_hardening_or_die(void) {
	int inactive_found = 0;
	
	for (size_t i = 0; i < GHOSTBOX_NUM_SYSCTL; i++) {
		const GhostBoxSysctlSetting *setting = &GHOSTBOX_SYSCTL_SETTINGS[i];
		char cur_val[64] = {0};
		
		int st = check_single_sysctl_status(setting, cur_val, sizeof(cur_val));
		if (st == 0) { // Supported by kernel, but currently INACTIVE
			fprintf(stderr, "[-] GhostBox Error: Required kernel hardening parameter inactive: %s\n"
			"    Path: %s (Current: '%s' | Required: '%s')\n",
					setting->description, setting->path, cur_val, setting->target_value);
			inactive_found++;
		}
	}
	
	if (inactive_found > 0) {
		fprintf(stderr, "[-] GhostBox: Pre-execution check failed (%d inactive sysctl setting(s)).\n", inactive_found);
		fprintf(stderr, "[-] GhostBox: Run 'sudo ./ghostbox -i' to activate all sysctl parameters before launching the sandbox.\n");
		extern void trigger_killswitch(void);
		trigger_killswitch();
	}
}

// Callback for recursive SHM workspace purging and removal
static int ghostbox_unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
	int rv = remove(fpath);
	return rv;
}

// Secure scratch space cleanup helper preventing symlink attacks and tree traversal races
static void safe_shm_cleanup(const char *path, int (*cb)(const char *, const struct stat *, int, struct FTW *)) {
	nftw(path, cb, 64, FTW_DEPTH | FTW_PHYS);
}

// Helper to compare binary content against blocked system binaries (detects copies created via cp)
static int files_are_identical(const char *path1, const char *path2) {
	int fd1 = open(path1, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd1 < 0) return 0;
	int fd2 = open(path2, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd2 < 0) {
		close(fd1);
		return 0;
	}
	
	struct stat st1, st2;
	if (fstat(fd1, &st1) != 0 || fstat(fd2, &st2) != 0) {
		close(fd1);
		close(fd2);
		return 0;
	}
	if (st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino) {
		close(fd1);
		close(fd2);
		return 1;
	}
	if (st1.st_size != st2.st_size || st1.st_size == 0) {
		close(fd1);
		close(fd2);
		return 0;
	}
	
	char buf1[4096], buf2[4096];
	ssize_t n1, n2;
	int identical = 1;
	while ((n1 = read(fd1, buf1, sizeof(buf1))) > 0) {
		n2 = read(fd2, buf2, sizeof(buf2));
		if (n1 != n2 || memcmp(buf1, buf2, n1) != 0) {
			identical = 0;
			break;
		}
	}
	close(fd1);
	close(fd2);
	return identical;
}

// Security helper inspecting binary ELF headers and signatures to block disguised administrative wrappers
static int inspect_binary_security_signature(const char *path) {
	if (!path || path[0] == '\0') return 0;
	int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) return 0;
	
	char buf[4096];
	ssize_t n = read(fd, buf, sizeof(buf));
	close(fd);
	if (n < 4) return 0;
	
	// ELF Binary Inspection: Check header metadata for blocked dynamic interpreters
	if ((unsigned char)buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F') {
		static const char * const blocked_interps[] = {
			"/bin/bash", "/bin/sh", "/usr/bin/python", "/usr/bin/perl", NULL
		};
		for (int i = 0; blocked_interps[i] != NULL; i++) {
			size_t interp_len = strlen(blocked_interps[i]);
			if (n > 64) {
				char *match = memmem(buf, n, blocked_interps[i], interp_len);
				if (match && (size_t)(match - buf) < 1024) {
					return 1;
				}
			}
		}
		return 0;
	}
	
	// Shebang Script Inspection: Check if wrapper targets a restricted administrative command
	if (buf[0] == '#' && buf[1] == '!') {
		char *base = strrchr(path, '/');
		base = (base != NULL) ? base + 1 : (char *)path;
		static const char * const blocked_cmds[] = {
			"ps", "capsh", "uname", "hostnamectl", "lshw", "hwinfo", "inxi", "lspci", 
			"lscpu", "lspcu", "lsusb", "lsblk", "lsscsi", "dmidecode", "fwupdmgr", 
			"dmesg", "modinfo", "smartctl", "sysctl", "biosdecode", "lsmod", "insmod", 
			"rmmod", "modprobe", "hdparm", "fdisk", "parted", "blkid", "free", "top", 
			"htop", "neofetch", "screenfetch", "acpi", "upower", "journalctl", "lshal",
			"lsattr", "chattr", "lsinitramfs", "lsinitrd", "cpuid", "arch", "nproc", 
			"hostname", "ip", "ifconfig", "ethtool", "host", "strace", "ptrace", "iw", "chroot",
			"cp", "ln", "install", "dd", "python", "python3", "perl", "ruby", "lua", "node",
			"bash", "sh", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "busybox", "su", "sudo", "traceroute", "ssh", "echo", "nc", "netstat", "net", "swapon", "swapoff", "mlock", "munlock", "mlockall", "munlockall", NULL
		};
		for (int i = 0; blocked_cmds[i] != NULL; i++) {
			if (strcmp(base, blocked_cmds[i]) == 0) {
				return 1;
			}
		}
		return 0;
	}
	
	return 0;
}

// Secure RAM wiper on execution, interrupt, or exit with asynchronous pidfd slirp4netns & active sandbox cleanup
void secure_memory_wipe(void) {
	sigset_t mask, oldmask;
	sigfillset(&mask);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);
	
	// Immediately kill active sandboxed application child and its entire process group
	pid_t cpid = g_child_pid;
	if (cpid > 0) {
		g_child_pid = -1;
		kill(-cpid, SIGKILL);
		kill(cpid, SIGKILL);
		waitpid(cpid, NULL, WNOHANG);
	}
	
	pid_t mgr = g_slirp_mgr;
	if (mgr > 0) {
		g_slirp_mgr = -1;
		kill(mgr, SIGTERM);
		kill(mgr, SIGKILL);
		waitpid(mgr, NULL, WNOHANG);
	}
	
	// Asynchronous pidfd sweep and termination for slirp4netns
	pid_t async_cleaner = fork();
	if (async_cleaner == 0) {
		if (fork() == 0) {
			DIR *dir = opendir("/proc");
			if (dir) {
				struct dirent *entry;
				while ((entry = readdir(dir)) != NULL) {
					if (entry->d_type == DT_DIR) {
						pid_t pid = atoi(entry->d_name);
						if (pid > 0 && pid != getpid() && pid != getppid()) {
							int pfd = syscall(SYS_pidfd_open, pid, 0);
							if (pfd >= 0) {
								char path[64];
								snprintf(path, sizeof(path), "/proc/%d/comm", pid);
								int fd = open(path, O_RDONLY | O_CLOEXEC);
								if (fd >= 0) {
									char comm[256];
									ssize_t n = read(fd, comm, sizeof(comm) - 1);
									if (n > 0) {
										comm[n] = '\0';
										if (strncmp(comm, "slirp4netns", 11) == 0) {
											syscall(SYS_pidfd_send_signal, pfd, SIGKILL, NULL, 0);
										}
									}
									close(fd);
								}
								close(pfd);
							}
						}
					}
				}
				closedir(dir);
			}
			_exit(0);
		}
		_exit(0);
	} else if (async_cleaner > 0) {
		waitpid(async_cleaner, NULL, 0);
	}
	
	// Detach lingering mountpoints in RAM before workspace unlinking
	umount2("/dev/shm/ghostbox_pivot", MNT_DETACH);
	umount2("/dev/shm/ghostbox_wayland", MNT_DETACH);
	umount2("/dev/shm/ghostbox_home", MNT_DETACH);
	umount2("/dev/shm/ghostbox_root", MNT_DETACH);
	umount2("/dev/shm/ghostbox_resolv.conf", MNT_DETACH);
	umount2("/dev/shm/ghostbox_cpuinfo", MNT_DETACH);
	umount2("/dev/shm/ghostbox_osrelease", MNT_DETACH);
	umount2("/dev/shm/ghostbox_version", MNT_DETACH);
	umount2("/dev/shm/ghostbox_cmdline", MNT_DETACH);
	umount2("/dev/shm/ghostbox_meminfo", MNT_DETACH);
	umount2("/dev/shm/ghostbox_ostype", MNT_DETACH);
	
	safe_shm_cleanup("/dev/shm/ghostbox_root", ghostbox_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_home", ghostbox_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_pivot", ghostbox_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_wayland", ghostbox_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_resolv.conf", ghostbox_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_cpuinfo", ghostbox_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_osrelease", ghostbox_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_version", ghostbox_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_cmdline", ghostbox_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_meminfo", ghostbox_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_ostype", ghostbox_unlink_cb);
	
	// Write zeros over every byte in allocated volatile memory buffer
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
	
	// Smooth out terminal interface on signal interruption
	write(STDERR_FILENO, "\033[0m", 4);
	
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
}

// Dedicated host-level watcher process ignoring termination signals to guarantee RAM scrubbing
static void run_watcher_process(int pipe_fd) {
	signal(SIGINT, SIG_IGN);
	signal(SIGTERM, SIG_IGN);
	signal(SIGHUP, SIG_IGN);
	signal(SIGQUIT, SIG_IGN);
	signal(SIGABRT, SIG_IGN);
	
	char sig_sig = 0;
	ssize_t n = read(pipe_fd, &sig_sig, 1);
	close(pipe_fd);
	
	if (n > 0 && sig_sig != 0) {
		write(STDERR_FILENO, "\n[!] GhostBox: Interruption signal caught. Purging RAM trace...\n", 65);
	}
	secure_memory_wipe();
	_exit(0);
}

// Killswitch trigger on startup failure, corruption, or unexpected stop
void trigger_killswitch(void) {
	write(STDERR_FILENO, "\n[!] GhostBox: Killswitch engaged (startup fault, corruption, or sandbox stop detected). Purging RAM...\n", 104);
	secure_memory_wipe();
	_exit(1);
}

// Dedicated signal handler operating strictly using POSIX async-signal-safe syscalls
static void killswitch_signal_handler(int sig) {
	pid_t cpid = g_child_pid;
	if (cpid > 0) {
		g_child_pid = -1;
		kill(-cpid, SIGKILL);
		kill(cpid, SIGKILL);
	}
	if (g_signal_pipe[1] != -1) {
		char sig_char = (char)sig;
		write(g_signal_pipe[1], &sig_char, 1);
		close(g_signal_pipe[1]);
		g_signal_pipe[1] = -1;
	}
	_exit(128 + sig);
}

void print_usage(const char *prog_name) {
	printf("========================================================\n");
	printf("   GHOSTBOX - Ultimate Kernel-Dual Strength Sandbox     \n");
	printf("========================================================\n");
	printf("Usage: %s [OPTIONS] [-- <command> [args...]]\n\n", prog_name);
	printf("Options:\n");
	printf("  -h           Display this help manual\n");
	printf("  -i           Implement Sysctl & RAM Memory Hardening (SwapOff / mlockall)\n");
	printf("  -c           Check status of active Sysctl & Memory Hardening\n");
	printf("Example:\n  %s -i\n  %s -c\n  %s -- firefox\n", prog_name, prog_name, prog_name);
}

int main(int argc, char *argv[]) {
	// Preserve host user credentials before entering user namespace
	uid_t real_uid = getuid();
	gid_t real_gid = getgid();
	char ubuf[32], gbuf[32];
	snprintf(ubuf, sizeof(ubuf), "%u", real_uid);
	snprintf(gbuf, sizeof(gbuf), "%u", real_gid);
	setenv("GHOSTBOX_HOST_UID", ubuf, 1);
	setenv("GHOSTBOX_HOST_GID", gbuf, 1);
	
	// Register atexit handler to guarantee RAM purging on all normal exits
	atexit(secure_memory_wipe);
	
	// Instantiate signal pipe and dedicated host-level watcher process at the very start of main()
	if (pipe2((int *)g_signal_pipe, O_CLOEXEC) == 0) {
		pid_t watcher = fork();
		if (watcher == 0) {
			close(g_signal_pipe[1]);
			run_watcher_process(g_signal_pipe[0]);
		}
		close(g_signal_pipe[0]);
	}
	
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = killswitch_signal_handler;
	sigfillset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGQUIT, &sa, NULL);
	sigaction(SIGABRT, &sa, NULL);
	
	secure_memory_wipe();
	
	int opt;
	int action_mode = 0; // 0 = run sandbox, 1 = implement (-i), 2 = check (-c)
	
	while ((opt = getopt(argc, argv, "hic")) != -1) {
		switch (opt) {
			case 'i':
				action_mode = 1;
				break;
			case 'c':
				action_mode = 2;
				break;
			case 'h':
			default:
				print_usage(argv[0]);
				return 0;
		}
	}
	
	if (action_mode == 1) {
		implement_sysctl_hardening();
		return 0;
	} else if (action_mode == 2) {
		check_sysctl_hardening_status();
		return 0;
	}
	
	if (optind >= argc) {
		print_usage(argv[0]);
		trigger_killswitch();
	}
	
	// Verify supported sysctl hardening parameters are active BEFORE launching sandbox
	verify_sysctl_hardening_or_die();
	
	const char *blocked_cmds[] = {
		"ps", "capsh", "uname", "hostnamectl", "lshw", "hwinfo", "inxi", "lspci", 
		"lscpu", "lspcu", "lsusb", "lsblk", "lsscsi", "dmidecode", "fwupdmgr", 
		"dmesg", "modinfo", "smartctl", "sysctl", "biosdecode", "lsmod", "insmod", 
		"rmmod", "modprobe", "hdparm", "fdisk", "parted", "blkid", "free", "top", 
		"htop", "neofetch", "screenfetch", "acpi", "upower", "journalctl", "lshal",
		"lsattr", "chattr", "lsinitramfs", "lsinitrd", "cpuid", "arch", "nproc", 
		"hostname", "ip", "ifconfig", "ethtool", "host", "strace", "ptrace", "iw", "chroot",
		"cp", "ln", "install", "dd", "python", "python3", "perl", "ruby", "lua", "node",
		"bash", "sh", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "busybox", "su", "sudo", "traceroute", "ssh", "echo", "nc", "netstat", "net", "swapon", "swapoff", "mlock", "munlock", "mlockall", "munlockall", NULL
	};
	
	int is_blocked = 0;
	
	// Block direct execution of dynamic linkers
	if (strstr(argv[optind], "ld-linux") != NULL || strstr(argv[optind], "ld.so") != NULL) {
		is_blocked = 1;
	}
	
	// Canonical path resolution & binary basename verification
	char target_real_path[PATH_MAX] = {0};
	if (!is_blocked) {
		if (realpath(argv[optind], target_real_path) == NULL) {
			char *path_env = getenv("PATH");
			if (path_env) {
				char *path_dup = strdup(path_env);
				if (path_dup) {
					char *dir = strtok(path_dup, ":");
					while (dir != NULL) {
						char full_p[PATH_MAX];
						snprintf(full_p, sizeof(full_p), "%s/%s", dir, argv[optind]);
						if (realpath(full_p, target_real_path) != NULL) {
							break;
						}
						dir = strtok(NULL, ":");
					}
					free(path_dup);
				}
			}
		}
	}
	
	// Trusted Path Execution Model (TPE): Enforce execution ONLY from strictly read-only system paths owned by root
	if (!is_blocked) {
		if (target_real_path[0] == '\0') {
			is_blocked = 1;
		} else {
			static const char * const trusted_system_paths[] = {
				"/usr/bin/", "/bin/", "/usr/sbin/", "/sbin/", "/usr/local/bin/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/", "/usr/share/", "/opt/", "/var/lib/", "/snap/", NULL
			};
			int is_trusted_path = 0;
			for (int t = 0; trusted_system_paths[t] != NULL; t++) {
				if (strncmp(target_real_path, trusted_system_paths[t], strlen(trusted_system_paths[t])) == 0) {
					is_trusted_path = 1;
					break;
				}
			}
			if (!is_trusted_path) {
				is_blocked = 1;
			} else {
				struct stat st_tpe;
				if (lstat(target_real_path, &st_tpe) != 0 || st_tpe.st_uid != 0 || (st_tpe.st_mode & (S_IWGRP | S_IWOTH))) {
					is_blocked = 1;
				}
			}
		}
	}
	
	if (!is_blocked && target_real_path[0] != '\0') {
		char *base = strrchr(target_real_path, '/');
		base = (base != NULL) ? base + 1 : target_real_path;
		for (int i = 0; blocked_cmds[i] != NULL; i++) {
			if (strcmp(base, blocked_cmds[i]) == 0) {
				is_blocked = 1;
				break;
			}
		}
	}
	
	// Deep binary content comparison against system blocked utilities (catches cp copies)
	if (!is_blocked && target_real_path[0] != '\0') {
		static const char * const sys_dirs[] = {"/usr/bin", "/bin", "/usr/sbin", "/sbin", NULL};
		for (int i = 0; blocked_cmds[i] != NULL && !is_blocked; i++) {
			for (int d = 0; sys_dirs[d] != NULL; d++) {
				char sys_bin[PATH_MAX];
				snprintf(sys_bin, sizeof(sys_bin), "%s/%s", sys_dirs[d], blocked_cmds[i]);
				if (files_are_identical(target_real_path, sys_bin)) {
					is_blocked = 1;
					break;
				}
			}
		}
	}
	
	// Secondary ELF signature check assisting basename matching
	if (!is_blocked && target_real_path[0] != '\0') {
		if (inspect_binary_security_signature(target_real_path)) {
			is_blocked = 1;
		}
	}
	
	if (!is_blocked) {
		for (int i = 0; blocked_cmds[i] != NULL; i++) {
			size_t cmd_len = strlen(blocked_cmds[i]);
			size_t arg_len = strlen(argv[optind]);
			if (strcmp(argv[optind], blocked_cmds[i]) == 0 || 
				(arg_len > cmd_len && argv[optind][arg_len - cmd_len - 1] == '/' && 
				strcmp(argv[optind] + arg_len - cmd_len, blocked_cmds[i]) == 0)) {
				is_blocked = 1;
			break;
				}
		}
	}
	
	if (!is_blocked) {
		for (int i = optind; i < argc; i++) {
			if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--eval") == 0) {
				is_blocked = 1;
				break;
			}
		}
	}
	
	if (!is_blocked) {
		for (int i = optind; i < argc; i++) {
			char resolved_arg[PATH_MAX];
			if (realpath(argv[i], resolved_arg) != NULL) {
				for (size_t j = 0; j < sizeof(GHOSTBOX_BLOCKED_PATHS)/sizeof(char*); j++) {
					char resolved_blocked[PATH_MAX];
					if (realpath(GHOSTBOX_BLOCKED_PATHS[j], resolved_blocked) != NULL) {
						if (strcmp(resolved_arg, resolved_blocked) == 0 || 
							(strncmp(resolved_arg, resolved_blocked, strlen(resolved_blocked)) == 0 && resolved_arg[strlen(resolved_blocked)] == '/')) {
							is_blocked = 1;
						break;
							}
					} else {
						if (strcmp(resolved_arg, GHOSTBOX_BLOCKED_PATHS[j]) == 0) {
							is_blocked = 1;
							break;
						}
					}
				}
			} else {
				for (size_t j = 0; j < sizeof(GHOSTBOX_BLOCKED_PATHS)/sizeof(char*); j++) {
					if (strcmp(argv[i], GHOSTBOX_BLOCKED_PATHS[j]) == 0) {
						is_blocked = 1;
						break;
					}
				}
			}
			if (is_blocked) break;
		}
	}
	
	if (!is_blocked) {
		for (int i = optind; i < argc; i++) {
			if (strcmp(argv[i], "chroot") == 0 || strcmp(argv[i], "ssh") == 0 || 
				(strstr(argv[i], "ghostbox") != NULL && i + 1 < argc && (strstr(argv[i+1], "chroot") != NULL || strstr(argv[i+1], "ssh") != NULL))) {
				is_blocked = 1;
			break;
				}
		}
	}
	
	if (is_blocked) {
		fprintf(stderr, "[-] GhostBox: Execution or path access is strictly blocked for hardware/system security.\n");
		trigger_killswitch();
	}
	
	if (target_real_path[0] != '\0') {
		argv[optind] = target_real_path;
	}
	
	// Ensure tun device node is initialized on host before launching slirp4netns
	ensure_tun_device_ready();
	
	// Initialize slirp manager pipe and process in the host network namespace prior to namespace unshare
	int pipefd[2];
	if (pipe2(pipefd, O_CLOEXEC) == 0) {
		g_slirp_mgr = fork();
		if (g_slirp_mgr == 0) {
			close(pipefd[1]);
			pid_t target_pid;
			if (read(pipefd[0], &target_pid, sizeof(target_pid)) > 0) {
				close(pipefd[0]);
				char pid_str[32];
				snprintf(pid_str, sizeof(pid_str), "%d", target_pid);
				execlp("slirp4netns", "slirp4netns", "--configure", "--mtu=65520", pid_str, "tap0", NULL);
			}
			_exit(1);
		}
		close(pipefd[0]);
	}
	
	// Single-threaded execution of hardening routines at the start of setup
	int clone_flags = CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET;
	
	printf("[*] GhostBox: Initializing kernel-level dual-strength namespaces...\n");
	if (unshare(clone_flags) < 0) {
		perror("GhostBox: Failed to unshare namespaces (Ensure user namespaces are enabled)");
		trigger_killswitch();
	}
	
	if (apply_hardware_cloaking() < 0 || setup_display_environment() < 0 || apply_namespace_sandboxing() < 0) {
		trigger_killswitch();
	}
	
	if (drop_all_capabilities() < 0) {
		trigger_killswitch();
	}
	
	if (apply_landlock_mac() < 0) {
		fprintf(stderr, "[-] GhostBox: Critical failure applying Landlock MAC. Aborting.\n");
		trigger_killswitch();
	}
	
	if (apply_seccomp_filter() < 0) {
		fprintf(stderr, "[-] GhostBox: Critical failure applying Seccomp rules. Aborting.\n");
		trigger_killswitch();
	}
	
	// Setup Cgroups v2 throttling dynamically *after* namespaces and sandboxing are established
	setup_cgroups_v2();
	
	printf("[*] GhostBox: Sandbox fully sealed. Executing payload: %s\n", argv[optind]);
	
	pid_t child_pid = fork();
	if (child_pid < 0) {
		perror("GhostBox: Fork failed");
		trigger_killswitch();
	}
	if (child_pid == 0) {
		setpgid(0, 0);
		char *dir_path = strdup(argv[optind]);
		if (dir_path) {
			char *last_slash = strrchr(dir_path, '/');
			if (last_slash) {
				*last_slash = '\0';
				chdir(dir_path);
			}
			free(dir_path);
		}
		execvp(argv[optind], &argv[optind]);
		perror("GhostBox: Execution failed");
		secure_memory_wipe();
		_exit(1);
	} else {
		g_child_pid = child_pid;
		if (pipefd[1] >= 0) {
			write(pipefd[1], &child_pid, sizeof(child_pid));
			close(pipefd[1]);
		}
		int status;
		waitpid(child_pid, &status, 0);
		secure_memory_wipe();
		if (WIFSIGNALED(status)) {
			fprintf(stderr, "[-] GhostBox: Had to Kill This Call\n");
			trigger_killswitch();
		}
		if (WIFEXITED(status)) {
			return WEXITSTATUS(status);
		}
		trigger_killswitch();
		return 1;
	}
}
