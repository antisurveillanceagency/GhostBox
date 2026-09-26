# GhostBox

GhostBox is a high-security, kernel-level dual-strength sandboxing and isolation engine written in C. Designed for uncompromising privacy and system hardening, it locks applications inside unprivileged namespaces, cloaks hardware profiles, enforces strict Seccomp-BPF system call whitelisting, and guarantees zero persistence via volatile RAM storage and automated secure memory wiping.

What It Does

GhostBox wraps target applications in multiple layers of kernel-enforced isolation, stripping away attack surfaces and preventing hardware fingerprinting or system leakage:

    Unprivileged Namespaces: Isolates processes using CLONE_NEWUSER, CLONE_NEWPID, CLONE_NEWNS, CLONE_NEWIPC, and CLONE_NEWUTS.

    Hardware & Path Cloaking: Overmounts sensitive system paths (/sys, /proc/cpuinfo, /proc/meminfo, /boot, /dev/mem, etc.) with tmpfs and spoofs system identification.

    Volatile RAM Storage: Redirects HOME, configuration, cache, and download directories directly to /dev/shm (RAM) to ensure files leave zero trace on disk.

    Seccomp-BPF Hardening: Restricts system calls using libseccomp with a strict whitelist (SCMP_ACT_KILL_PROCESS), instantly terminating any unauthorized syscall attempts.

    Capability Stripping: Drops all Linux capabilities (0–41) and disables core dumps (PR_SET_DUMPABLE).

Core Security Features

    1ms XDP Fail-Safe Killswitch: Instantly engages on startup faults, corruption, or unexpected sandbox termination, triggering an immediate memory wipe and exit.

    Recursive RAM Wiper: Automatically purges and zeroes out runtime files and allocated memory buffers upon execution, interruption, or exit.

    Memory Locking: Locks process memory into RAM using mlockall to prevent sensitive data from hitting swap partitions.

    Environment Scrubbing: Clears dangerous environment variables (HISTFILE, SSH_CLIENT, SSH_CONNECTION, USER) and isolates display contexts.

Quick Start
Compilation

Build GhostBox using gcc with required security and capability flags:
Bash

gcc -O3 ghostbox.c walls.c blockage.c -o ghostbox -lseccomp -lcap

Usage

Run any command or application securely inside the sandbox:
Bash

./ghostbox -- firefox

Display the help manual:
Bash

./ghostbox -h
