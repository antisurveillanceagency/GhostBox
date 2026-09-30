#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/swap.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>

void print_usage(const char *prog_name) {
	printf("========================================================\n");
	printf("   SWAPOFF & MLOCKALL HARDENING UTILITY                 \n");
	printf("========================================================\n");
	printf("Usage: %s [OPTIONS]\n\n", prog_name);
	printf("Options:\n");
	printf("  -s           Start: Disable all swap and enable mlockall\n");
	printf("  -c           Check: Inspect swap status and mlockall/locking state\n");
	printf("  -r           Revert: Re-enable swap and disable mlockall\n");
	printf("  -h           Display this help manual\n");
}

int disable_all_swap(void) {
	FILE *f = fopen("/proc/swaps", "r");
	if (!f) return -1;
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
				fprintf(stdout, "[*] SwapOff: Disabled swap device: %s\n", dev);
				count++;
			} else {
				perror("SwapOff: Failed to disable swap device");
			}
		}
	}
	fclose(f);
	return count;
}

int start_hardening(void) {
	struct rlimit rl = {RLIM_INFINITY, RLIM_INFINITY};
	if (setrlimit(RLIMIT_MEMLOCK, &rl) < 0) {
		perror("SwapOff: Failed to set RLIMIT_MEMLOCK to infinity");
	}
	
	disable_all_swap();
	
	if (mlockall(MCL_CURRENT | MCL_FUTURE) < 0) {
		perror("SwapOff: mlockall failed");
		fprintf(stderr, "[-] SwapOff: mlockall status: FAILED\n");
		return -1;
	} else {
		fprintf(stdout, "[+] SwapOff: mlockall active and swap disabled with unlimited locking space.\n");
	}
	return 0;
}

int check_status(void) {
	int swap_active = 0;
	FILE *f = fopen("/proc/swaps", "r");
	if (f) {
		char line[256];
		int lines = 0;
		while (fgets(line, sizeof(line), f)) {
			lines++;
		}
		fclose(f);
		if (lines > 1) {
			swap_active = 1;
		}
	}
	
	struct rlimit rl;
	int mlock_limit_unlimited = 0;
	if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
		if (rl.rlim_cur == RLIM_INFINITY) {
			mlock_limit_unlimited = 1;
		}
	}
	
	printf("========================================================\n");
	printf("   SWAPOFF & MLOCKALL STATUS INSPECTION                 \n");
	printf("========================================================\n");
	if (swap_active) {
		printf("[!] Swap Status: ACTIVE (Swap devices/files are currently enabled)\n");
	} else {
		printf("[+] Swap Status: DISABLED (No active swap devices found)\n");
	}
	
	if (mlock_limit_unlimited) {
		printf("[+] MEMLOCK Limit: UNLIMITED (RLIMIT_MEMLOCK is set to infinity)\n");
	} else {
		printf("[!] MEMLOCK Limit: RESTRICTED\n");
	}
	return 0;
}

int revert_hardening(void) {
	if (munlockall() < 0) {
		perror("SwapOff: munlockall failed");
	} else {
		fprintf(stdout, "[*] SwapOff: mlockall disabled / memory unlocked.\n");
	}
	
	int ret = -1;
	pid_t pid = fork();
	if (pid == 0) {
		execlp("/sbin/swapon", "swapon", "-a", NULL);
		execlp("swapon", "swapon", "-a", NULL);
		_exit(1);
	} else if (pid > 0) {
		int status;
		if (waitpid(pid, &status, 0) > 0 && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
			ret = 0;
		}
	}
	
	if (ret == 0) {
		fprintf(stdout, "[+] SwapOff: Swap devices re-enabled successfully via swapon -a.\n");
	} else {
		perror("SwapOff: Failed to re-enable swap via swapon -a");
	}
	return 0;
}

int main(int argc, char *argv[]) {
	if (getuid() != 0) {
		fprintf(stderr, "[-] SwapOff: This utility must be executed with root privileges.\n");
		return 1;
	}
	
	if (argc < 2) {
		print_usage(argv[0]);
		return 1;
	}
	
	int opt;
	while ((opt = getopt(argc, argv, "hscr")) != -1) {
		switch (opt) {
			case 's':
				return start_hardening();
			case 'c':
				return check_status();
			case 'r':
				return revert_hardening();
			case 'h':
			default:
				print_usage(argv[0]);
				return 0;
		}
	}
	
	if (optind < argc) {
		start_hardening();
		execvp(argv[optind], &argv[optind]);
		perror("SwapOff: execvp failed");
		return 1;
	}
	
	print_usage(argv[0]);
	return 0;
}
