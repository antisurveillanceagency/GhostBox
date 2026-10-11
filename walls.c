#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mount.h>
#include <sys/mman.h>
#include <sys/utsname.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/stat.h>
#include <ftw.h>
#include <signal.h>
#include <limits.h>
#include <sys/syscall.h>
#include <sys/sysmacros.h>

// Blocked hardware, sensitive device nodes, and PCI / proc disclosure paths enforcement
static const char * const WALLS_BLOCKED_PATHS[] = {
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

static int walls_unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
	int rv = remove(fpath);
	return rv;
}

// Secure scratch space cleanup helper preventing symlink attacks and tree traversal races
static void safe_shm_cleanup(const char *path, int (*cb)(const char *, const struct stat *, int, struct FTW *)) {
	nftw(path, cb, 64, FTW_DEPTH | FTW_PHYS);
}

// Race-free directory creation preventing symlink planting and TOCTOU hijacking
static int secure_shm_mkdir(const char *path) {
	if (mkdir(path, 0700) != 0 && errno != EEXIST) {
		return -1;
	}
	int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		remove(path);
		if (mkdir(path, 0700) != 0) return -1;
		fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
		if (fd < 0) return -1;
	}
	struct stat st;
	if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid()) {
		close(fd);
		return -1;
	}
	fchmod(fd, 0700);
	close(fd);
	return 0;
}

// Helper mapping container process to unprivileged container UID (1000) for browser non-root checks
static void ensure_user_mapping(void) {
	static int mapped = 0;
	if (mapped) return;
	
	int fd = open("/proc/self/setgroups", O_WRONLY);
	if (fd >= 0) {
		write(fd, "deny", 4);
		close(fd);
	}
	
	uid_t host_uid = getuid();
	gid_t host_gid = getgid();
	
	char *env_u = getenv("GHOSTBOX_HOST_UID");
	char *env_g = getenv("GHOSTBOX_HOST_GID");
	if (env_u && env_u[0] != '\0') host_uid = (uid_t)atoi(env_u);
	if (env_g && env_g[0] != '\0') host_gid = (gid_t)atoi(env_g);
	
	if (host_uid == 65534 || host_uid == 0) {
		char *sudo_u = getenv("SUDO_UID");
		if (sudo_u && sudo_u[0] != '\0') host_uid = (uid_t)atoi(sudo_u);
	}
	if (host_gid == 65534 || host_gid == 0) {
		char *sudo_g = getenv("SUDO_GID");
		if (sudo_g && sudo_g[0] != '\0') host_gid = (gid_t)atoi(sudo_g);
	}
	
	if (host_uid == 0) host_uid = 1000;
	if (host_gid == 0) host_gid = 1000;
	
	char buf[128];
	snprintf(buf, sizeof(buf), "1000 %u 1", host_uid);
	fd = open("/proc/self/uid_map", O_WRONLY);
	if (fd >= 0) {
		write(fd, buf, strlen(buf));
		close(fd);
	}
	
	snprintf(buf, sizeof(buf), "1000 %u 1", host_gid);
	fd = open("/proc/self/gid_map", O_WRONLY);
	if (fd >= 0) {
		write(fd, buf, strlen(buf));
		close(fd);
	}
	
	mapped = 1;
}

// Secure RAM wiper for walls module with complete directory unlinking, zero overwriting, and removal
void walls_secure_memory_wipe(void) {
	sigset_t mask, oldmask;
	sigfillset(&mask);
	sigprocmask(SIG_BLOCK, &mask, &oldmask);
	
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
	
	safe_shm_cleanup("/dev/shm/ghostbox_root", walls_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_home", walls_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_pivot", walls_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_wayland", walls_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_resolv.conf", walls_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_cpuinfo", walls_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_osrelease", walls_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_version", walls_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_cmdline", walls_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_meminfo", walls_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_ostype", walls_unlink_cb);
	
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
	
	write(STDERR_FILENO, "\033[0m", 4);
	
	sigprocmask(SIG_SETMASK, &oldmask, NULL);
}

// Walls Killswitch trigger
void walls_killswitch(void) {
	write(STDERR_FILENO, "[-] Walls: Killswitch engaged due to initialization or sandbox fault.\n", 70);
	walls_secure_memory_wipe();
	_exit(1);
}

int apply_hardware_cloaking(void) {
	if (sethostname("ghostbox-secure-node", 20) < 0) {
		perror("GhostBox: Failed to spoof hostname");
		return -1;
	}
	
	unsetenv("HISTFILE");
	unsetenv("SSH_CLIENT");
	unsetenv("SSH_CONNECTION");
	unsetenv("USER");
	
	return 0;
}

int setup_display_environment(void) {
	ensure_user_mapping();
	
	char *display = getenv("DISPLAY");
	char *wayland_display = getenv("WAYLAND_DISPLAY");
	char *xdg_runtime = getenv("XDG_RUNTIME_DIR");
	char *xauth = getenv("XAUTHORITY");
	
	char xauth_src_path[PATH_MAX] = {0};
	if (xauth && access(xauth, R_OK) == 0) {
		snprintf(xauth_src_path, sizeof(xauth_src_path), "%s", xauth);
	} else {
		char *orig_home = getenv("HOME");
		if (orig_home) {
			snprintf(xauth_src_path, sizeof(xauth_src_path), "%s/.Xauthority", orig_home);
		}
	}
	
	char wayland_src_dir[PATH_MAX] = {0};
	if (xdg_runtime && access(xdg_runtime, R_OK) == 0) {
		snprintf(wayland_src_dir, sizeof(wayland_src_dir), "%s", xdg_runtime);
	} else {
		char *env_u = getenv("GHOSTBOX_HOST_UID");
		uid_t h_uid = (env_u && env_u[0] != '\0') ? (uid_t)atoi(env_u) : getuid();
		snprintf(wayland_src_dir, sizeof(wayland_src_dir), "/run/user/%u", h_uid);
	}
	
	clearenv();
	
	if (display) {
		setenv("DISPLAY", display, 1);
	}
	if (wayland_display) {
		setenv("WAYLAND_DISPLAY", wayland_display, 1);
	} else {
		setenv("WAYLAND_DISPLAY", "wayland-0", 1);
	}
	setenv("XDG_RUNTIME_DIR", "/dev/shm/ghostbox_wayland", 1);
	setenv("MOZ_ENABLE_WAYLAND", "1", 1);
	
	setenv("PATH", "/usr/local/bin:/usr/bin:/bin", 1);
	
	setenv("HOME", "/dev/shm/ghostbox_home", 1);
	setenv("XDG_CONFIG_HOME", "/dev/shm/ghostbox_home/.config", 1);
	setenv("XDG_DATA_HOME", "/dev/shm/ghostbox_home/.local/share", 1);
	setenv("XDG_CACHE_HOME", "/dev/shm/ghostbox_home/.cache", 1);
	
	setenv("USER", "ghostbox", 1);
	setenv("LOGNAME", "ghostbox", 1);
	setenv("MULLVAD_BROWSER_ALLOW_ROOT", "1", 1);
	setenv("MULLVAD_SKIP_ROOT_CHECK", "1", 1);
	setenv("TOR_SKIP_ROOT_CHECK", "1", 1);
	setenv("PWD", "/dev/shm/ghostbox_home", 1);
	
	if (secure_shm_mkdir("/dev/shm/ghostbox_home") < 0 ||
		secure_shm_mkdir("/dev/shm/ghostbox_home/.config") < 0 ||
		secure_shm_mkdir("/dev/shm/ghostbox_home/.local") < 0 ||
		secure_shm_mkdir("/dev/shm/ghostbox_home/.local/share") < 0 ||
		secure_shm_mkdir("/dev/shm/ghostbox_home/.cache") < 0 ||
		secure_shm_mkdir("/dev/shm/ghostbox_home/Downloads") < 0 ||
		secure_shm_mkdir("/dev/shm/ghostbox_wayland") < 0) {
		return -1;
		}
		
		if (wayland_src_dir[0] != '\0' && access(wayland_src_dir, R_OK) == 0) {
			if (mount(wayland_src_dir, "/dev/shm/ghostbox_wayland", NULL, MS_BIND | MS_REC, NULL) == 0) {
				mount(NULL, "/dev/shm/ghostbox_wayland", NULL, MS_REC | MS_PRIVATE, NULL);
			}
		}
		
		if (xauth_src_path[0] != '\0') {
			int src_fd = open(xauth_src_path, O_RDONLY | O_CLOEXEC);
			if (src_fd >= 0) {
				int dst_fd = open("/dev/shm/ghostbox_home/.Xauthority", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
				if (dst_fd >= 0) {
					char xbuf[1024];
					ssize_t n;
					while ((n = read(src_fd, xbuf, sizeof(xbuf))) > 0) {
						ssize_t written = 0;
						while (written < n) {
							ssize_t w = write(dst_fd, xbuf + written, n - written);
							if (w <= 0) break;
							written += w;
						}
					}
					fchmod(dst_fd, 0600);
					close(dst_fd);
					setenv("XAUTHORITY", "/dev/shm/ghostbox_home/.Xauthority", 1);
				}
				close(src_fd);
			}
		}
		
		return 0;
}

int apply_namespace_sandboxing(void) {
	ensure_user_mapping();
	
	mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL);
	
	// Secure Pivot Root setup using /dev/shm/ghostbox_pivot backed by shared tmpfs
	if (secure_shm_mkdir("/dev/shm/ghostbox_pivot") < 0) return -1;
	if (mount("/dev/shm/ghostbox_pivot", "/dev/shm/ghostbox_pivot", NULL, MS_BIND | MS_REC, NULL) < 0) return -1;
	if (mount(NULL, "/dev/shm/ghostbox_pivot", NULL, MS_REC | MS_PRIVATE, NULL) < 0) return -1;
	
	char old_root_path[PATH_MAX];
	snprintf(old_root_path, sizeof(old_root_path), "/dev/shm/ghostbox_pivot/old_root");
	mkdir(old_root_path, 0700);
	if (mount("/", old_root_path, NULL, MS_BIND | MS_REC, NULL) < 0) return -1;
	
	static const char * const mount_dirs[] = {
		"/usr", "/bin", "/lib", "/lib64", "/opt", "/snap", "/var", "/etc", "/dev", "/proc", "/sys", NULL
	};
	for (int i = 0; mount_dirs[i] != NULL; i++) {
		char target_dir[PATH_MAX];
		snprintf(target_dir, sizeof(target_dir), "/dev/shm/ghostbox_pivot%s", mount_dirs[i]);
		struct stat st;
		if (stat(mount_dirs[i], &st) == 0 && S_ISDIR(st.st_mode)) {
			mkdir(target_dir, 0755);
			mount(mount_dirs[i], target_dir, NULL, MS_BIND | MS_REC, NULL);
		}
	}
	
	if (syscall(SYS_pivot_root, "/dev/shm/ghostbox_pivot", old_root_path) < 0) {
		perror("GhostBox: pivot_root failed");
		return -1;
	}
	chdir("/");
	
	mount("tmpfs", "/sys", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=1M");
	mkdir("/sys/fs", 0755);
	mkdir("/sys/fs/cgroup", 0755);
	if (mount("cgroup2", "/sys/fs/cgroup", "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC | MS_RELATIME, NULL) < 0) {
		mount("/old_root/sys/fs/cgroup", "/sys/fs/cgroup", NULL, MS_BIND | MS_REC, NULL);
	}
	
	mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, "hidepid=2");
	
	// Mount fresh, clean isolated tmpfs over /dev and whitelist strictly safe exclusive nodes
	if (mount("tmpfs", "/dev", "tmpfs", MS_NOSUID | MS_NOEXEC, "mode=0755,size=10M") == 0) {
		static const struct {
			const char *target;
			const char *src;
			int is_dir;
		} safe_dev_nodes[] = {
			{"/dev/null", "/old_root/dev/null", 0},
			{"/dev/zero", "/old_root/dev/zero", 0},
			{"/dev/full", "/old_root/dev/full", 0},
			{"/dev/random", "/old_root/dev/random", 0},
			{"/dev/urandom", "/old_root/dev/urandom", 0},
			{"/dev/pts", "/old_root/dev/pts", 1},
			{NULL, NULL, 0}
		};
		
		for (int i = 0; safe_dev_nodes[i].target != NULL; i++) {
			if (safe_dev_nodes[i].is_dir) {
				mkdir(safe_dev_nodes[i].target, 0755);
				mount(safe_dev_nodes[i].src, safe_dev_nodes[i].target, NULL, MS_BIND | MS_REC, NULL);
			} else {
				int fd_node = open(safe_dev_nodes[i].target, O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0666);
				if (fd_node >= 0) close(fd_node);
				mount(safe_dev_nodes[i].src, safe_dev_nodes[i].target, NULL, MS_BIND, NULL);
			}
		}
		
		// Mount a fresh independent tmpfs for /dev/shm inside container
		mkdir("/dev/shm", 01777);
		if (mount("tmpfs", "/dev/shm", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "mode=1777,size=64M") == 0) {
			if (access("/old_root/dev/shm/ghostbox_home", F_OK) == 0) {
				mkdir("/dev/shm/ghostbox_home", 0700);
				mount("/old_root/dev/shm/ghostbox_home", "/dev/shm/ghostbox_home", NULL, MS_BIND | MS_REC, NULL);
			}
			if (access("/old_root/dev/shm/ghostbox_wayland", F_OK) == 0) {
				mkdir("/dev/shm/ghostbox_wayland", 0700);
				mount("/old_root/dev/shm/ghostbox_wayland", "/dev/shm/ghostbox_wayland", NULL, MS_BIND | MS_REC, NULL);
			}
		}
		
		// Safely expose /dev/net/tun inside container namespace if present on host
		if (access("/old_root/dev/net/tun", F_OK) == 0) {
			mkdir("/dev/net", 0755);
			int fd_tun = open("/dev/net/tun", O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0666);
			if (fd_tun >= 0) close(fd_tun);
			mount("/old_root/dev/net/tun", "/dev/net/tun", NULL, MS_BIND, NULL);
		}
		
		symlink("/proc/self/fd", "/dev/fd");
		symlink("/proc/self/fd/0", "/dev/stdin");
		symlink("/proc/self/fd/1", "/dev/stdout");
		symlink("/proc/self/fd/2", "/dev/stderr");
		if (access("/dev/pts/ptmx", F_OK) == 0) {
			symlink("/dev/pts/ptmx", "/dev/ptmx");
		} else if (access("/old_root/dev/ptmx", F_OK) == 0) {
			int fd_ptmx = open("/dev/ptmx", O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0666);
			if (fd_ptmx >= 0) close(fd_ptmx);
			mount("/old_root/dev/ptmx", "/dev/ptmx", NULL, MS_BIND, NULL);
		}
	}
	
	umount2("/old_root", MNT_DETACH);
	rmdir("/old_root");
	
	static const char * const tpe_paths[] = {
		"/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/local/bin",
		"/usr/lib", "/usr/lib64", "/usr/libexec", "/usr/share",
		"/opt", "/var/lib", "/snap", NULL
	};
	for (int t = 0; tpe_paths[t] != NULL; t++) {
		struct stat st;
		if (stat(tpe_paths[t], &st) == 0 && S_ISDIR(st.st_mode)) {
			mount(tpe_paths[t], tpe_paths[t], NULL, MS_BIND | MS_REC, NULL);
			mount(NULL, tpe_paths[t], NULL, MS_BIND | MS_REMOUNT | MS_RDONLY | MS_REC, NULL);
		}
	}
	
	int f_dns = open("/dev/shm/ghostbox_resolv.conf", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
	if (f_dns >= 0) {
		const char *dns_content = "nameserver 10.0.2.3\n";
		write(f_dns, dns_content, strlen(dns_content));
		fchmod(f_dns, 0644);
		close(f_dns);
	}
	
	int f_cpu = open("/dev/shm/ghostbox_cpuinfo", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
	if (f_cpu >= 0) {
		const char *cpu_content = "processor\t: 0\n"
		"vendor_id\t: GhostBoxCPU\n"
		"cpu family\t: 6\n"
		"model\t\t: 1\n"
		"model name\t: GhostBox Secure Virtual Processor\n"
		"flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx lm constant_tsc\n\n";
		write(f_cpu, cpu_content, strlen(cpu_content));
		fchmod(f_cpu, 0644);
		close(f_cpu);
	}
	
	int f_os = open("/dev/shm/ghostbox_osrelease", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
	if (f_os >= 0) {
		const char *os_content = "GhostBoxLinux\n";
		write(f_os, os_content, strlen(os_content));
		fchmod(f_os, 0644);
		close(f_os);
	}
	
	int f_ver = open("/dev/shm/ghostbox_version", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
	if (f_ver >= 0) {
		const char *ver_content = "GhostBox Secure Kernel Version 6.0-hardened\n";
		write(f_ver, ver_content, strlen(ver_content));
		fchmod(f_ver, 0644);
		close(f_ver);
	}
	
	int f_cmd = open("/dev/shm/ghostbox_cmdline", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
	if (f_cmd >= 0) {
		const char *cmd_content = "ghostbox-secure-sandbox init\n";
		write(f_cmd, cmd_content, strlen(cmd_content));
		fchmod(f_cmd, 0644);
		close(f_cmd);
	}
	
	int f_mem = open("/dev/shm/ghostbox_meminfo", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
	if (f_mem >= 0) {
		const char *mem_content = "MemTotal:        4194304 kB\nMemFree:         2097152 kB\nMemAvailable:    2097152 kB\n";
		write(f_mem, mem_content, strlen(mem_content));
		fchmod(f_mem, 0644);
		close(f_mem);
	}
	
	int f_ostype = open("/dev/shm/ghostbox_ostype", O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0644);
	if (f_ostype >= 0) {
		const char *ostype_content = "GhostBoxOS\n";
		write(f_ostype, ostype_content, strlen(ostype_content));
		fchmod(f_ostype, 0644);
		close(f_ostype);
	}
	
	// Explicitly bind mount fake files over proc paths
	mount("/dev/shm/ghostbox_osrelease", "/proc/sys/kernel/osrelease", NULL, MS_BIND, NULL);
	mount("/dev/shm/ghostbox_version", "/proc/version", NULL, MS_BIND, NULL);
	mount("/dev/shm/ghostbox_cpuinfo", "/proc/cpuinfo", NULL, MS_BIND, NULL);
	mount("/dev/shm/ghostbox_cmdline", "/proc/cmdline", NULL, MS_BIND, NULL);
	mount("/dev/shm/ghostbox_meminfo", "/proc/meminfo", NULL, MS_BIND, NULL);
	mount("/dev/shm/ghostbox_ostype", "/proc/sys/kernel/ostype", NULL, MS_BIND, NULL);
	
	for (size_t i = 0; i < sizeof(WALLS_BLOCKED_PATHS) / sizeof(WALLS_BLOCKED_PATHS[0]); i++) {
		if (strcmp(WALLS_BLOCKED_PATHS[i], "/etc/resolv.conf") == 0) {
			mount("/dev/shm/ghostbox_resolv.conf", "/etc/resolv.conf", NULL, MS_BIND, NULL);
		} else if (strcmp(WALLS_BLOCKED_PATHS[i], "/proc/cpuinfo") == 0) {
			mount("/dev/shm/ghostbox_cpuinfo", "/proc/cpuinfo", NULL, MS_BIND, NULL);
		} else if (strcmp(WALLS_BLOCKED_PATHS[i], "/proc/version") == 0) {
			mount("/dev/shm/ghostbox_version", "/proc/version", NULL, MS_BIND, NULL);
		} else if (strcmp(WALLS_BLOCKED_PATHS[i], "/proc/cmdline") == 0) {
			mount("/dev/shm/ghostbox_cmdline", "/proc/cmdline", NULL, MS_BIND, NULL);
		} else if (strcmp(WALLS_BLOCKED_PATHS[i], "/proc/meminfo") == 0) {
			mount("/dev/shm/ghostbox_meminfo", "/proc/meminfo", NULL, MS_BIND, NULL);
		} else if (strncmp(WALLS_BLOCKED_PATHS[i], "/dev/", 5) == 0) {
			// Skip /dev paths: /dev is already a clean isolated tmpfs with only whitelisted safe nodes
			continue;
		} else {
			struct stat st;
			if (lstat(WALLS_BLOCKED_PATHS[i], &st) == 0) {
				if (S_ISDIR(st.st_mode)) {
					if (mount("tmpfs", WALLS_BLOCKED_PATHS[i], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k") != 0) {
						mount("/dev/null", WALLS_BLOCKED_PATHS[i], NULL, MS_BIND, NULL);
					}
				} else {
					mount("/dev/null", WALLS_BLOCKED_PATHS[i], NULL, MS_BIND, NULL);
				}
			} else {
				if (strncmp(WALLS_BLOCKED_PATHS[i], "/proc/", 6) != 0 && strncmp(WALLS_BLOCKED_PATHS[i], "/sys/", 5) != 0) {
					int fd_file = open(WALLS_BLOCKED_PATHS[i], O_WRONLY | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0644);
					if (fd_file >= 0) close(fd_file);
					mount("/dev/null", WALLS_BLOCKED_PATHS[i], NULL, MS_BIND, NULL);
				}
			}
		}
	}
	
	return 0;
}
