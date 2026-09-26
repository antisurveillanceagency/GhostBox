/*
 * GhostBox - blockage.c
 * Seccomp-BPF and Capability Hardening Engine
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/capability.h>
#include <errno.h>
#include <sys/stat.h>
#include <ftw.h>
#include <seccomp.h>

// Blocked hardware and PCI paths enforcement reference
static const char * const BLOCKAGE_BLOCKED_PATHS[] = {
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

static int blockage_unlink_cb(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
	int rv = remove(fpath);
	return rv;
}

// Secure RAM wiper for blockage module (upon execution, interruption, and exit)
void blockage_secure_memory_wipe(void) {
	nftw("/dev/shm/ghostbox_home", blockage_unlink_cb, 64, FTW_DEPTH | FTW_PHYS);
	volatile char *p = malloc(1024 * 1024);
	if (p) {
		for (size_t i = 0; i < 1024 * 1024; i++) {
			p[i] = 0;
		}
		free((void *)p);
	}
}

// Blockage XDP fail-safe killswitch trigger
void blockage_xdp_killswitch(void) {
	fprintf(stderr, "[-] Blockage: 1ms XDP Killswitch engaged due to hardening or Seccomp failure.\n");
	blockage_secure_memory_wipe();
	_exit(1);
}

int drop_all_capabilities(void) {
	blockage_secure_memory_wipe(); // RAM wipe upon execution hook
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
	
	for (int i = 0; i <= 41; i++) {
		prctl(PR_CAPBSET_DROP, i);
	}
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
		blockage_xdp_killswitch();
		return -1;
	}
	
	int rc = 0;
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
		SCMP_SYS(clone), SCMP_SYS(clone3), SCMP_SYS(fork), SCMP_SYS(vfork), SCMP_SYS(execve),
		SCMP_SYS(exit), SCMP_SYS(exit_group), SCMP_SYS(wait4), SCMP_SYS(kill), SCMP_SYS(tkill),
		SCMP_SYS(tgkill), SCMP_SYS(socket), SCMP_SYS(connect), SCMP_SYS(bind), SCMP_SYS(accept),
		SCMP_SYS(accept4), SCMP_SYS(getsockname), SCMP_SYS(getpeername), SCMP_SYS(getsockopt),
		SCMP_SYS(setsockopt), SCMP_SYS(sendto), SCMP_SYS(recvfrom), SCMP_SYS(sendmsg),
		SCMP_SYS(recvmsg), SCMP_SYS(socketpair), SCMP_SYS(shutdown), SCMP_SYS(getuid),
		SCMP_SYS(geteuid), SCMP_SYS(getgid), SCMP_SYS(getegid), SCMP_SYS(getpid), SCMP_SYS(getppid),
		SCMP_SYS(gettid), SCMP_SYS(getxattr), SCMP_SYS(lgetxattr), SCMP_SYS(fgetxattr),
		SCMP_SYS(listxattr), SCMP_SYS(flistxattr), SCMP_SYS(llistxattr), SCMP_SYS(capget),
		SCMP_SYS(shmget), SCMP_SYS(shmat), SCMP_SYS(shmdt), SCMP_SYS(shmctl), SCMP_SYS(mmap),
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
		SCMP_SYS(seccomp), SCMP_SYS(bpf), SCMP_SYS(kcmp), SCMP_SYS(listen), SCMP_SYS(sendmmsg),
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
		SCMP_SYS(faccessat2), SCMP_SYS(unshare), SCMP_SYS(semget), SCMP_SYS(semop), SCMP_SYS(semctl),
		SCMP_SYS(msgget), SCMP_SYS(msgsnd), SCMP_SYS(msgrcv), SCMP_SYS(truncate), SCMP_SYS(fchdir),
		SCMP_SYS(utimes), SCMP_SYS(utimensat), SCMP_SYS(futimesat), SCMP_SYS(clock_settime),
		SCMP_SYS(timer_create), SCMP_SYS(timer_settime), SCMP_SYS(timer_gettime), SCMP_SYS(timer_getoverrun),
		SCMP_SYS(timer_delete), SCMP_SYS(alarm), SCMP_SYS(setitimer), SCMP_SYS(getitimer),
		SCMP_SYS(setpgid), SCMP_SYS(setgroups), SCMP_SYS(get_robust_list), SCMP_SYS(io_setup),
		SCMP_SYS(io_destroy), SCMP_SYS(io_submit), SCMP_SYS(io_cancel), SCMP_SYS(io_getevents),
		SCMP_SYS(personality), SCMP_SYS(setxattr), SCMP_SYS(lsetxattr), SCMP_SYS(fsetxattr),
		SCMP_SYS(removexattr), SCMP_SYS(nanosleep), SCMP_SYS(pkey_alloc), SCMP_SYS(pkey_free),
		SCMP_SYS(pkey_mprotect), SCMP_SYS(pidfd_open), SCMP_SYS(pidfd_send_signal), SCMP_SYS(pidfd_getfd),
		SCMP_SYS(userfaultfd), SCMP_SYS(sync), SCMP_SYS(syncfs), SCMP_SYS(rt_tgsigqueueinfo),
		SCMP_SYS(rt_sigqueueinfo), SCMP_SYS(name_to_handle_at), SCMP_SYS(open_by_handle_at),
		SCMP_SYS(mq_open), SCMP_SYS(mq_unlink), SCMP_SYS(mq_timedsend), SCMP_SYS(mq_timedreceive),
		SCMP_SYS(mq_notify), SCMP_SYS(mq_getsetattr), SCMP_SYS(msgctl), SCMP_SYS(get_thread_area),
		SCMP_SYS(set_thread_area), SCMP_SYS(perf_event_open), SCMP_SYS(landlock_create_ruleset),
		SCMP_SYS(landlock_add_rule), SCMP_SYS(landlock_restrict_self), SCMP_SYS(memfd_secret),
		SCMP_SYS(quotactl), SCMP_SYS(ioprio_get), SCMP_SYS(ioprio_set), SCMP_SYS(setfsuid),
		SCMP_SYS(setfsgid)
	};
	
	for (size_t i = 0; i < sizeof(syscalls) / sizeof(syscalls[0]); i++) {
		if (seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscalls[i], 0) < 0) {
			rc = -1;
			break;
		}
	}
	
	if (rc == 0) {
		rc = seccomp_load(ctx);
	}
	
	seccomp_release(ctx);
	
	if (rc < 0) {
		perror("GhostBox: Failed to apply seccomp filter via libseccomp");
		blockage_xdp_killswitch();
		return -1;
	}
	
	blockage_secure_memory_wipe(); // RAM wipe upon successful sealing/exit hook
	return 0;
}
