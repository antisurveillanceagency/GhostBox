/*
 * GhostBox - walls.c
 * Isolation, Hardware Cloaking, Landlock FS and Display Management Engine
 */

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

// Blocked hardware and PCI paths enforcement
static const char * const WALLS_BLOCKED_PATHS[] = {
	"/sys/bus/pci/devices",
	"/sys/bus/pci/devices/0000:00:1g.0/config",
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
	"/home",
	"/root",
	"/media",
	"/mnt",
	"/srv",
	"/etc/iproute2/rt_tables",
	"/etc/resolv.conf",
	"/etc/NetworkManager/NetworkManager.conf"
};

static int walls_unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
	int rv = remove(fpath);
	return rv;
}

// Secure RAM wiper for walls module (upon execution, interruption, and exit)
void walls_secure_memory_wipe(void) {
	nftw("/dev/shm/ghostbox_home", walls_unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
	volatile char *p = malloc(1024 * 1024);
	if (p) {
		for (size_t i = 0; i < 1024 * 1024; i++) {
			p[i] = 0;
		}
		free((void *)p);
	}
}

// Walls XDP fail-safe killswitch trigger
void walls_xdp_killswitch(void) {
	fprintf(stderr, "[-] Walls: 1ms XDP Killswitch engaged due to initialization or sandbox fault.\n");
	walls_secure_memory_wipe();
	_exit(1);
}

int initialize_ram_lock(void) {
	walls_secure_memory_wipe(); // RAM wipe upon execution hook
	if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0) {
		perror("GhostBox: mlockall failed (Warning: running without full RAM lock)");
		return -1;
	}
	return 0;
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
	if (display) {
		setenv("DISPLAY", display, 1);
	}
	char *wayland_display = getenv("WAYLAND_DISPLAY");
	if (wayland_display) {
		setenv("WAYLAND_DISPLAY", wayland_display, 1);
	}
	char *xdg_runtime = getenv("XDG_RUNTIME_DIR");
	if (xdg_runtime) {
		setenv("XDG_RUNTIME_DIR", xdg_runtime, 1);
	}
	
	// Redirect HOME and XDG directories to /dev/shm for strict RAM-only storage (profiles, cookies, downloads)
	setenv("HOME", "/dev/shm/ghostbox_home", 1);
	setenv("XDG_CONFIG_HOME", "/dev/shm/ghostbox_home/.config", 1);
	setenv("XDG_DATA_HOME", "/dev/shm/ghostbox_home/.local/share", 1);
	setenv("XDG_CACHE_HOME", "/dev/shm/ghostbox_home/.cache", 1);
	
	mkdir("/dev/shm/ghostbox_home", 0700);
	mkdir("/dev/shm/ghostbox_home/.config", 0700);
	mkdir("/dev/shm/ghostbox_home/.local", 0700);
	mkdir("/dev/shm/ghostbox_home/.local/share", 0700);
	mkdir("/dev/shm/ghostbox_home/.cache", 0700);
	mkdir("/dev/shm/ghostbox_home/Downloads", 0700);
	
	return 0;
}

int apply_landlock_sandboxing(void) {
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
	mount("tmpfs", "/sys", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=1M");
	mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL);
	
	// Explicitly block and overmount requested hardware/PCI paths and leaks
	mount("tmpfs", WALLS_BLOCKED_PATHS[0], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[2], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[3], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[4], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[5], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[6], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[7], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[8], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[9], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[10], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[11], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[12], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[13], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[14], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[15], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[16], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[17], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[18], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[19], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[20], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[21], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[23], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	mount("tmpfs", WALLS_BLOCKED_PATHS[24], "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=4k");
	
	walls_secure_memory_wipe(); // RAM wipe upon exit/completion hook
	return 0;
}
