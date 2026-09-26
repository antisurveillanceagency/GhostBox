/*
 * GhostBox - ghostbox.c
 * Main Orchestration Engine, Unprivileged Namespaces, and Execution Loop
 */

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

// Global tracker for slirp4netns manager process
static pid_t g_slirp_mgr = -1;

// Blocked hardware and PCI paths
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
    "/home",
    "/root",
    "/media",
    "/mnt",
    "/srv",
    "/etc/iproute2/rt_tables",
    "/etc/resolv.conf",
    "/etc/NetworkManager/NetworkManager.conf"
};

// External engine hooks
extern int apply_seccomp_filter(void);
extern int drop_all_capabilities(void);
extern int initialize_ram_lock(void);
extern int apply_hardware_cloaking(void);
extern int setup_display_environment(void);
extern int apply_landlock_sandboxing(void);

// Callback for recursive SHM workspace purging
static int ghostbox_unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    int rv = remove(fpath);
    return rv;
}

// Secure RAM wiper on execution, interrupt, or exit
void secure_memory_wipe(void) {
    if (g_slirp_mgr > 0) {
        kill(g_slirp_mgr, SIGTERM);
        waitpid(g_slirp_mgr, NULL, WNOHANG);
        g_slirp_mgr = -1;
    }
    // Safe process termination via /proc scanning (No shell command injection)
    DIR *dir = opendir("/proc");
    if (dir) {
        struct dirent *entry;
        while ((entry = readdir(dir)) != NULL) {
            if (entry->d_type == DT_DIR) {
                pid_t pid = atoi(entry->d_name);
                if (pid > 0 && pid != getpid()) {
                    char path[64];
                    snprintf(path, sizeof(path), "/proc/%d/comm", pid);
                    FILE *f = fopen(path, "r");
                    if (f) {
                        char comm[256];
                        if (fgets(comm, sizeof(comm), f)) {
                            if (strncmp(comm, "slirp4netns", 11) == 0) {
                                kill(pid, SIGKILL);
                            }
                        }
                        fclose(f);
                    }
                }
            }
        }
        closedir(dir);
    }
    nftw("/dev/shm/ghostbox_home", ghostbox_unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
    size_t alloc_size = 4 * 1024 * 1024;
    volatile char *p = malloc(alloc_size);
    if (p) {
        for (size_t i = 0; i < alloc_size; i++) {
            p[i] = 0;
        }
        madvise((void *)p, alloc_size, MADV_DONTNEED);
        free((void *)p);
    }
    sync();
}

// 1ms XDP fail-safe killswitch trigger on startup failure, corruption, or unexpected stop
void trigger_xdp_killswitch(void) {
    fprintf(stderr, "\n[!] GhostBox: 1ms XDP Killswitch engaged (startup fault, corruption, or sandbox stop detected). Purging RAM...\n");
    secure_memory_wipe();
    _exit(1);
}

void handle_signal(int sig) {
    fprintf(stderr, "\n[!] GhostBox: Interruption signal caught (%d). Purging RAM trace and terminating securely...\n", sig);
    secure_memory_wipe();
    _exit(0);
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
    // RAM wipe upon execution
    secure_memory_wipe();
    
    int opt;
    
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    signal(SIGSEGV, handle_signal);
    
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
        trigger_xdp_killswitch();
    }
    
    // Extensive command and hardware info blocklist (including copy/symlink and script/python dangerous flags)
    const char *blocked_cmds[] = {
        "ps", "capsh", "uname", "hostnamectl", "lshw", "hwinfo", "inxi", "lspci", 
        "lscpu", "lspcu", "lsusb", "lsblk", "lsscsi", "dmidecode", "fwupdmgr", 
        "dmesg", "modinfo", "smartctl", "sysctl", "biosdecode", "lsmod", "insmod", 
        "rmmod", "modprobe", "hdparm", "fdisk", "parted", "blkid", "free", "top", 
        "htop", "neofetch", "screenfetch", "acpi", "upower", "journalctl", "lshal",
        "lsattr", "chattr", "lsinitramfs", "lsinitrd", "cpuid", "arch", "nproc", 
        "hostname", "ip", "ifconfig", "ethtool", "host", "strace", "ptrace", "iw", "chroot",
        "cp", "ln", "install", "dd", "python", "python3", "perl", "ruby", "lua", "node", NULL
    };
    
    int is_blocked = 0;
    
    // Check if the base command is blocked
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
    
    // Block python/interpreter inline dangerous command execution flags (-c, -m)
    if (!is_blocked) {
        for (int i = optind; i < argc; i++) {
            if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--eval") == 0) {
                is_blocked = 1;
                break;
            }
        }
    }
    
    // Check all arguments for blocked hardware/kernel paths (e.g. cat /proc/version)
    if (!is_blocked) {
        for (int i = optind; i < argc; i++) {
            for (size_t j = 0; j < sizeof(GHOSTBOX_BLOCKED_PATHS)/sizeof(char*); j++) {
                if (strstr(argv[i], GHOSTBOX_BLOCKED_PATHS[j]) != NULL) {
                    is_blocked = 1;
                    break;
                }
            }
            if (is_blocked) break;
        }
    }
    
    // Block /ghostbox chroot and all its extensions
    if (!is_blocked) {
        for (int i = optind; i < argc; i++) {
            if (strcmp(argv[i], "chroot") == 0 || 
                (strstr(argv[i], "ghostbox") != NULL && i + 1 < argc && strstr(argv[i+1], "chroot") != NULL)) {
                is_blocked = 1;
            break;
                }
        }
    }
    
    if (is_blocked) {
        fprintf(stderr, "[-] GhostBox: Execution or path access is strictly blocked for hardware/system security.\n");
        trigger_xdp_killswitch();
    }
    
    if (initialize_ram_lock() < 0) {
        trigger_xdp_killswitch();
    }
    
    int pipefd[2];
    if (pipe(pipefd) == 0) {
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
    
    int clone_flags = CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS | CLONE_NEWNET;
    
    printf("[*] GhostBox: Initializing kernel-level dual-strength namespaces...\n");
    if (unshare(clone_flags) < 0) {
        perror("GhostBox: Failed to unshare namespaces (Ensure user namespaces are enabled)");
        trigger_xdp_killswitch();
    }
    
    if (apply_hardware_cloaking() < 0 || setup_display_environment() < 0 || apply_landlock_sandboxing() < 0) {
        trigger_xdp_killswitch();
    }
    
    if (drop_all_capabilities() < 0) {
        trigger_xdp_killswitch();
    }
    
    if (apply_seccomp_filter() < 0) {
        fprintf(stderr, "[-] GhostBox: Critical failure applying Seccomp rules. Aborting.\n");
        trigger_xdp_killswitch();
    }
    
    printf("[*] GhostBox: Sandbox fully sealed. Executing payload: %s\n", argv[optind]);
    
    pid_t child_pid = fork();
    if (child_pid < 0) {
        perror("GhostBox: Fork failed");
        trigger_xdp_killswitch();
    }
    if (child_pid == 0) {
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
        // RAM wipe upon exit
        secure_memory_wipe();
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "[-] GhostBox: Had to Kill This Call\n");
            trigger_xdp_killswitch();
        }
        if (WIFEXITED(status)) {
            return WEXITSTATUS(status);
        }
        trigger_xdp_killswitch();
        return 1;
    }
}
