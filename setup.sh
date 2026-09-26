#!/usr/bin/env bash
# ========================================================
#   GHOSTBOX - Automated Setup, Dependency & Build Script
# ========================================================

# Exit immediately if any command fails
set -e

echo "[*] GhostBox Setup: Checking execution privileges..."
if [ "$EUID" -ne 0 ]; then
	echo "[!] Error: This script must be run with sudo or as root to install package dependencies."
	echo "[!] Usage: sudo ./setup.sh"
	exit 1
	fi
	
	echo "[*] GhostBox Setup: Updating system package repositories..."
	apt-get update -y
	
	echo "[*] GhostBox Setup: Installing build tools, security headers, and network bridging tools..."
	apt-get install -y \
	build-essential \
	libcap-dev \
	libseccomp-dev slirp4netns \
	
	echo "[*] GhostBox Setup: Verifying core source files..."
	required_files=("ghostbox.c" "walls.c" "blockage.c")
	for file in "${required_files[@]}"; do
		if [ ! -f "$file" ]; then
			echo "[-] Critical Error: Missing required source file -> $file"
			echo "[-] Please ensure ghostbox.c, walls.c, and blockage.c are in the current working directory."
			exit 1
			fi
			done
			
			echo "[*] GhostBox Setup: Compiling static binary with optimization level -O3..."
			gcc -O3 -static ghostbox.c walls.c blockage.c -lcap -lseccomp -o ghostbox
			
			echo "[*] GhostBox Setup: Stripping binary debug symbols for anti-forensic minimization..."
			strip --strip-all ghostbox
			
			echo "========================================================"
			echo "   [+] GHOSTBOX INSTALLATION SUCCESSFUL!                "
			echo "========================================================"
			echo "Executable compiled: ./ghostbox"
			echo "To test isolation, run: ./ghostbox -- /bin/bash"
			echo "To launch network apps, run: ./ghostbox -- firefox"
			echo "========================================================"
