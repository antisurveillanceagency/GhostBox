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

// Blocked hardware, sensitive device nodes, and PCI paths enforcement
static const char * const WALLS_BLOCKED_PATHS[] = {
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

static int walls_unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
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

// Race-free directory creation preventing symlink planting and TOCTOU hijacking
static int secure_shm_mkdir(const char *path) {
	struct stat st;
	if (lstat(path, &st) == 0) {
		if (S_ISLNK(st.st_mode) || !S_ISDIR(st.st_mode) || st.st_uid != getuid()) {
			safe_shm_cleanup(path, walls_unlink_cb);
		}
	}
	if (mkdir(path, 0700) != 0 && errno != EEXIST) {
		return -1;
	}
	int fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
	if (fd < 0) {
		return -1;
	}
	if (fstat(fd, &st) != 0 || !S_ISDIR(st.st_mode) || st.st_uid != getuid()) {
		close(fd);
		return -1;
	}
	chmod(path, 0700);
	close(fd);
	return 0;
}

// Secure RAM wiper for walls module with complete directory unlinking and removal
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
	
	safe_shm_cleanup("/dev/shm/ghostbox_root", walls_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_home", walls_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_pivot", walls_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_wayland", walls_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_resolv.conf", walls_unlink_cb);
	safe_shm_cleanup("/dev/shm/ghostbox_cpuinfo", walls_unlink_cb);
	
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

// Walls Killswitch trigger
void walls_killswitch(void) {
	fprintf(stderr, "[-] Walls: Killswitch engaged due to initialization or sandbox fault.\n");
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
		snprintf(wayland_src_dir, sizeof(wayland_src_dir), "/run/user/%d", getuid());
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
	
	setenv("USER", "root", 1);
	setenv("LOGNAME", "root", 1);
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
			mount(wayland_src_dir, "/dev/shm/ghostbox_wayland", NULL, MS_BIND | MS_REC, NULL);
			mount(NULL, "/dev/shm/ghostbox_wayland", NULL, MS_REC | MS_PRIVATE, NULL);
		}
		
		if (xauth_src_path[0] != '\0' && access(xauth_src_path, R_OK) == 0) {
			FILE *src = fopen(xauth_src_path, "rb");
			if (src) {
				FILE *dst = fopen("/dev/shm/ghostbox_home/.Xauthority", "wb");
				if (dst) {
					char xbuf[1024];
					size_t n;
					while ((n = fread(xbuf, 1, sizeof(xbuf), src)) > 0) {
						fwrite(xbuf, 1, n, dst);
					}
					fclose(dst);
					chmod("/dev/shm/ghostbox_home/.Xauthority", 0600);
					setenv("XAUTHORITY", "/dev/shm/ghostbox_home/.Xauthority", 1);
				}
				fclose(src);
			}
		}
		
		return 0;
}

int apply_namespace_sandboxing(void) {
	int fd = open("/proc/self/setgroups", O_WRONLY);
	if (fd >= 0) {
		write(fd, "deny", 4);
		close(fd);
	}
	
	char buf[128];
	uid_t uid = getuid();
	gid_t gid = getgid();
	
	snprintf(buf, sizeof(buf), "0 %d 1", uid);
	fd = open("/proc/self/uid_map", O_WRONLY);
	if (fd >= 0) {
		write(fd, buf, strlen(buf));
		close(fd);
	}
	
	snprintf(buf, sizeof(buf), "0 %d 1", gid);
	fd = open("/proc/self/gid_map", O_WRONLY);
	if (fd >= 0) {
		write(fd, buf, strlen(buf));
		close(fd);
	}
	
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
	umount2("/old_root", MNT_DETACH);
	rmdir("/old_root");
	
	mount("tmpfs", "/sys", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=1M");
	mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
	
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
	
	FILE *f_dns = fopen("/dev/shm/ghostbox_resolv.conf", "w");
	if (f_dns) {
		fprintf(f_dns, "nameserver 10.0.2.3\n");
		fclose(f_dns);
		chmod("/dev/shm/ghostbox_resolv.conf", 0644);
	}
	
	FILE *f_cpu = fopen("/dev/shm/ghostbox_cpuinfo", "w");
	if (f_cpu) {
		fprintf(f_cpu, "processor\t: 0\n"
		"vendor_id\t: GenuineIntel\n"
		"cpu family\t: 6\n"
		"model\t\t: 158\n"
		"model name\t: GhostBox Cloaked CPU\n"
		"flags\t\t: fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat pse36 clflush mmx fxsr sse sse2 ss ht syscall nx lm constant_tsc rep_good nopl xtopology tsc_reliable nonstoptsc pni pclmulqdq ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt tsc_deadline_timer aes xsave avx f16c rdrand hypervisor\n\n");
		fclose(f_cpu);
		chmod("/dev/shm/ghostbox_cpuinfo", 0644);
	}
	
	for (size_t i = 0; i < sizeof(WALLS_BLOCKED_PATHS) / sizeof(WALLS_BLOCKED_PATHS[0]); i++) {
		if (strcmp(WALLS_BLOCKED_PATHS[i], "/etc/resolv.conf") == 0) {
			mount("/dev/shm/ghostbox_resolv.conf", "/etc/resolv.conf", NULL, MS_BIND, NULL);
		} else if (strcmp(WALLS_BLOCKED_PATHS[i], "/proc/cpuinfo") == 0) {
			mount("/dev/shm/ghostbox_cpuinfo", "/proc/cpuinfo", NULL, MS_BIND, NULL);
		} else {
			struct stat st;
			if (stat(WALLS_BLOCKED_PATHS[i], &st) == 0 && S_ISDIR(st.st_mode)) {
				mkdir(WALLS_BLOCKED_PATHS[i], 0755);
				if (mount("tmpfs", WALLS_BLOCKED_PATHS[i], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k") != 0) {
					mount("/dev/null", WALLS_BLOCKED_PATHS[i], NULL, MS_BIND, NULL);
				}
			} else {
				int fd_file = open(WALLS_BLOCKED_PATHS[i], O_WRONLY | O_CREAT, 0644);
				if (fd_file >= 0) close(fd_file);
				mount("/dev/null", WALLS_BLOCKED_PATHS[i], NULL, MS_BIND, NULL);
			}
		}
	}
	
	return 0;
}
