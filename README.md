# GhostBox

Tested Linux Distros: ParrotOS

Tested Browsers: Firefox, Librewolf & Mullvad Browser
(Tor Browser is not yet working with GhostBox due to a high risk sys call)

GhostBox is a high-security, kernel-level dual-strength sandboxing and isolation engine written in C. Designed for uncompromising privacy and system hardening, it locks applications inside unprivileged namespaces, cloaks hardware profiles, enforces strict Seccomp-BPF system call whitelisting, and guarantees zero persistence via volatile RAM storage and automated secure memory wiping.

## What It Does

GhostBox wraps target applications in multiple layers of kernel-enforced isolation, stripping away attack surfaces and preventing hardware fingerprinting or system leakage:

* **Unprivileged Namespaces:** Isolates processes using `CLONE_NEWUSER`, `CLONE_NEWPID`, `CLONE_NEWNS`, `CLONE_NEWIPC`, `CLONE_NEWUTS`, and `CLONE_NEWNET`.
* **Secure Pivot Root (`pivot_root`):** Establishes an isolated root filesystem backed by a secure `tmpfs` workspace (`/dev/shm/ghostbox_pivot`), mounting only essential system directories read-only and detaching the host's old root entirely.
* **Landlock Mandatory Access Control (MAC):** Enforces kernel-level filesystem restrictions and restricts network binding/connections to approved proxy, DNS, and web ports (supporting Landlock ABIs 1–5).
* **Slirp4netns Networking Integration:** Connects the sandbox via an unprivileged user-space network manager and virtual `tap0` interface with a custom MTU (`65520`).
* **Hardware & Path Cloaking:** Overmounts sensitive system paths (`/sys`, `/proc/cpuinfo`, `/proc/meminfo`, `/boot`, `/dev/mem`, etc.) with `tmpfs` and spoofs system identification.
* **Volatile RAM Storage:** Redirects `HOME`, configuration, cache, and download directories directly to `/dev/shm` (RAM) to ensure files leave zero trace on disk.
* **Seccomp-BPF Hardening:** Restricts system calls using `libseccomp` with a strict whitelist (`SCMP_ACT_KILL_PROCESS`), instantly terminating any unauthorized syscall attempts.
* **Capability Stripping:** Drops all Linux capabilities (0–63) and disables core dumps (`PR_SET_DUMPABLE`).

## Core Security Features

* **Trusted Path Execution (TPE) & Binary Inspection:** Enforces execution strictly from approved system paths and performs byte-by-byte content comparison (`files_are_identical`) alongside ELF/shebang header checks to defeat binary copying and wrapper bypasses.
* **Killswitch:** Instantly engages on startup faults, corruption, or unexpected sandbox termination, triggering an immediate memory wipe and exit.
* **Async Signal Watcher & Pidfd Sweep:** Utilizes a secure `pipe2` watcher process and `pidfd` tracking (`pidfd_open` / `pidfd_send_signal`) to safely locate and terminate lingering network daemons on interruption or crash.
* **Recursive RAM Wiper:** Automatically purges, unmounts, and zeroes out runtime files and allocated memory buffers upon execution, interruption, or exit.
* **Memory Locking:** Locks process memory into RAM using `mlockall` to prevent sensitive data from hitting swap partitions.
* **Environment Scrubbing:** Clears dangerous environment variables (`HISTFILE`, `SSH_CLIENT`, `SSH_CONNECTION`, `USER`) and isolates display contexts.

## Quick Start

### Compilation

NEVER EVER RUN GHOSTBOX AS SUDO/ROOT

Build GhostBox using `gcc` with required security and capability flags:
```bash
gcc -O3 -static ghostbox.c walls.c blockage.c -lcap -lseccomp -o ghostbox

gcc -O3 -static swapoff.c -o swapoff


./ghostbox firefox (example usage)

sudo ./swapoff -h (help commands)

Please enable swapoff before you run ghostbox.
