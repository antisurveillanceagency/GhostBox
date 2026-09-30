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

#ifndef SYS_pidfd_open
#define SYS_pidfd_open 434
#endif
#ifndef SYS_pidfd_send_signal
#define SYS_pidfd_send_signal 424
#endif

// Global tracker for slirp4netns manager process and volatile signal pipe for secure async cleanup
static volatile sig_atomic_t g_slirp_mgr = -1;
static volatile int g_signal_pipe[2] = {-1, -1};

// Blocked hardware, sensitive device nodes, and system paths
static const char * const GHOSTBOX_BLOCKED_PATHS[] = {
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

// External engine hooks
extern int apply_seccomp_filter(void);
extern int drop_all_capabilities(void);
extern int apply_hardware_cloaking(void);
extern int setup_display_environment(void);
extern int apply_namespace_sandboxing(void);
extern int apply_landlock_mac(void);

// Callback for recursive SHM workspace purging and removal
static int ghostbox_unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
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

// Helper to compare binary content against blocked system binaries (detects copies created via cp)
static int files_are_identical(const char *path1, const char *path2) {
	struct stat st1, st2;
	if (stat(path1, &st1) != 0 || stat(path2, &st2) != 0) return 0;
	if (st1.st_dev == st2.st_dev && st1.st_ino == st2.st_ino) return 1;
	if (st1.st_size != st2.st_size || st1.st_size == 0) return 0;
	FILE *f1 = fopen(path1, "rb");
	FILE *f2 = fopen(path2, "rb");
	if (!f1 || !f2) {
		if (f1) fclose(f1);
		if (f2) fclose(f2);
		return 0;
	}
	char buf1[4096], buf2[4096];
	size_t n1, n2;
	int identical = 1;
	while ((n1 = fread(buf1, 1, sizeof(buf1), f1)) > 0) {
		n2 = fread(buf2, 1, sizeof(buf2), f2);
		if (n1 != n2 || memcmp(buf1, buf2, n1) != 0) {
			identical = 0;
			break;
		}
	}
	fclose(f1);
	fclose(f2);
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
			"bash", "sh", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "busybox", "su", "sudo", "traceroute", "ssh", "echo", "nc", NULL
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

// Secure RAM wiper on execution, interrupt, or exit with asynchronous pidfd slirp4netns cleanup
void secure_memory_wipe(void) {
	sigset_t mask, oldmask;
	sigfillset(&mask);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);
	
	pid_t mgr = g_slirp_mgr;
	if (mgr > 0) {
		g_slirp_mgr = -1;
		kill(mgr, SIGTERM);
		waitpid(mgr, NULL, WNOHANG);
	}
	
	// Asynchronous pidfd sweep and termination for slirp4netns
	pid_t async_cleaner = fork();
	if (async_cleaner == 0) {
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
							FILE *f = fopen(path, "r");
							if (f) {
								char comm[256];
								if (fgets(comm, sizeof(comm), f)) {
									if (strncmp(comm, "slirp4netns", 11) == 0) {
										syscall(SYS_pidfd_send_signal, pfd, SIGKILL, NULL, 0);
									}
								}
								fclose(f);
							}
							close(pfd);
						}
					}
				}
			}
			closedir(dir);
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
	
	safe_shm_cleanup("/dev/shm/ghostbox_root", ghostbox_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_home", ghostbox_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_pivot", ghostbox_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_wayland", ghostbox_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_resolv.conf", ghostbox_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_cpuinfo", ghostbox_unlink_cb);
	
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

// Killswitch trigger on startup failure, corruption, or unexpected stop
void trigger_killswitch(void) {
	fprintf(stderr, "\n[!] GhostBox: Killswitch engaged (startup fault, corruption, or sandbox stop detected). Purging RAM...\n");
	secure_memory_wipe();
	_exit(1);
}

// Dedicated signal handler for immediate killswitch invocation on interruption or segmentation fault (Async-signal-safe)
static void killswitch_signal_handler(int sig) {
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
	printf("Usage: %s [OPTIONS] -- <command> [args...]\n\n", prog_name);
	printf("Options:\n");
	printf("  -h           Display this help manual\n");
	printf("Example:\n  %s -- firefox\n", prog_name);
}

int main(int argc, char *argv[]) {
	// Instantiate signal pipe and watcher process at the very start of main()
	if (pipe2((int *)g_signal_pipe, O_CLOEXEC) == 0) {
		pid_t watcher = fork();
		if (watcher == 0) {
			close(g_signal_pipe[1]);
			char sig_sig;
			ssize_t n = read(g_signal_pipe[0], &sig_sig, 1);
			close(g_signal_pipe[0]);
			if (n > 0) {
				fprintf(stderr, "\n[!] GhostBox: Interruption signal caught (%d). Purging RAM trace and terminating securely...\n", (int)sig_sig);
				secure_memory_wipe();
				_exit(128 + sig_sig);
			}
			secure_memory_wipe();
			_exit(0);
		}
		close(g_signal_pipe[0]);
	}
	
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = killswitch_signal_handler;
	sigfillset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
	
	secure_memory_wipe();
	
	int opt;
	
	while ((opt = getopt(argc, argv, "h")) != -1) {
		switch (opt) {
			case 'h':
			default:
				print_usage(argv[0]);
				return 0;
		}
	}
	
	if (optind >= argc) {
		print_usage(argv[0]);
		trigger_killswitch();
	}
	
	const char *blocked_cmds[] = {
		"ps", "capsh", "uname", "hostnamectl", "lshw", "hwinfo", "inxi", "lspci", 
		"lscpu", "lspcu", "lsusb", "lsblk", "lsscsi", "dmidecode", "fwupdmgr", 
		"dmesg", "modinfo", "smartctl", "sysctl", "biosdecode", "lsmod", "insmod", 
		"rmmod", "modprobe", "hdparm", "fdisk", "parted", "blkid", "free", "top", 
		"htop", "neofetch", "screenfetch", "acpi", "upower", "journalctl", "lshal",
		"lsattr", "chattr", "lsinitramfs", "lsinitrd", "cpuid", "arch", "nproc", 
		"hostname", "ip", "ifconfig", "ethtool", "host", "strace", "ptrace", "iw", "chroot",
		"cp", "ln", "install", "dd", "python", "python3", "perl", "ruby", "lua", "node",
		"bash", "sh", "zsh", "dash", "ksh", "csh", "tcsh", "fish", "busybox", "su", "sudo", "traceroute", "ssh", "echo", "nc", NULL
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
	
	// Trusted Path Execution Model (TPE): Enforce execution ONLY from strictly read-only system paths
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
				if (access(sys_bin, F_OK) == 0) {
					if (files_are_identical(target_real_path, sys_bin)) {
						is_blocked = 1;
						break;
					}
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
	
	printf("[*] GhostBox: Sandbox fully sealed. Executing payload: %s\n", argv[optind]);
	
	pid_t child_pid = fork();
	if (child_pid < 0) {
		perror("GhostBox: Fork failed");
		trigger_killswitch();
	}
	if (child_pid == 0) {
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
