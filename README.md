# Project 3: Network Intrusion Detection Engineering

**Name:** Dulwan A.G.B  
**Student ID:** IT24101302  

Welcome to the **Network Intrusion Detection Engineering** project repository. This codebase provides a complete end-to-end framework, custom Snort rule engineering, detection coverage mapping, performance benchmarking reports, and automation scripts.

## Directory Structure

```text
network_ids_project/
├── rules/
│   └── local.rules                       # 10 Custom Snort rules with classtype & MITRE mappings
├── matrix/
│   └── detection_coverage_matrix.csv     # Complete mapping of attacks, SIDs, MITRE IDs, & severities
├── reports/
│   └── performance_benchmark_report.md   # CPU/memory benchmarks & false-positive evaluation
├── documentation/
│   └── detection_logic_guide.md          # In-depth packet attribute & detection rationale per SID
└── scripts/
    └── lab_setup_and_test.sh             # Bash script for deployment, live IDS, & offline PCAP testing
```

## Quick Start Guide

### 1. Lab Setup (VirtualBox / VMware)
*   **Attacker Machine**: Kali Linux (IP e.g., `192.168.56.101`)
*   **Defender Host**: Ubuntu 22.04 LTS (IP e.g., `192.168.56.102`)
*   **Adapter**: Internal Network (`Internalnet` / `Host-Only`)

### 2. Deploying Custom Rules & Testing
On your Ubuntu Defender machine:
```bash
# Clone or copy project files to Defender host
chmod +x scripts/lab_setup_and_test.sh
sudo ./scripts/lab_setup_and_test.sh
```

### 3. Running Live Detection
```bash
sudo snort -A console -q -u snort -g snort -c /etc/snort/snort.conf -i eth0
```

### 4. Simulating Attacks from Kali Linux
```bash
# Example 1: ICMP Ping Sweep
nmap -sn 192.168.56.0/24

# Example 2: SSH Brute Force
msfconsole -x "use auxiliary/scanner/ssh/ssh_login; set RHOSTS 192.168.56.102; set USERPASS_FILE /usr/share/wordlists/metasploit/root_userpass.txt; run; exit"

# Example 3: TCP SYN Flood
sudo hping3 -S --flood -p 80 192.168.56.102
```

### 5. False Positive & Benchmark Testing
```bash
# Test against normal traffic baseline (expect 0 alerts)
sudo snort -r baseline.pcap -c /etc/snort/snort.conf

# Benchmark rule performance against attack capture
sudo snort -r attack.pcap -c /etc/snort/snort.conf -l /var/log/snort/
```