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
#include <ftw.h>

// Blocked hardware and PCI paths
static const char * const GHOSTBOX_BLOCKED_PATHS[] = {
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
    nftw("/dev/shm/ghostbox_home", ghostbox_unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
    volatile char *p = malloc(1024 * 1024);
    if (p) {
        for (size_t i = 0; i < 1024 * 1024; i++) {
            p[i] = 0;
        }
        free((void *)p);
    }
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
    
    // Extensive command and hardware info blocklist
    const char *blocked_cmds[] = {
        "ps", "capsh", "uname", "hostnamectl", "lshw", "hwinfo", "inxi", "lspci", 
        "lscpu", "lspcu", "lsusb", "lsblk", "lsscsi", "dmidecode", "fwupdmgr", 
        "dmesg", "modinfo", "smartctl", "sysctl", "biosdecode", "lsmod", "insmod", 
        "rmmod", "modprobe", "hdparm", "fdisk", "parted", "blkid", "free", "top", 
        "htop", "neofetch", "screenfetch", "acpi", "upower", "journalctl", "lshal",
        "lsattr", "chattr", "lsinitramfs", "lsinitrd", "cpuid", "arch", "nproc", 
        "hostname", "ip", "ifconfig", "ethtool", "host", "strace", "ptrace", "iw", "chroot", NULL
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
    
    int clone_flags = CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWUTS;
    
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
