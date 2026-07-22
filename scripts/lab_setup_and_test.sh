#!/usr/bin/env bash
# ==============================================================================
# Network Intrusion Detection Engineering - Lab Setup & Testing Script
# Name: Dulwan A.G.B
# Attacker Environment: Kali Linux
# Target Host: Ubuntu / Debian Linux Defender Machine
# ==============================================================================

set -euo pipefail

RULES_DIR="/etc/snort/rules"
CONF_FILE="/etc/snort/snort.conf"
LOG_DIR="/var/log/snort"
INTERFACE="eth0"

echo "[+] Step 1: Installing Prerequisites & Snort IDS..."
sudo apt-get update -qq
sudo apt-get install -y -qq snort wireshark tshark hping3 net-tools

echo "[+] Step 2: Preparing Snort Directory Structure..."
sudo mkdir -p "${RULES_DIR}" "${LOG_DIR}"
sudo touch /etc/snort/rules/white_list.rules /etc/snort/rules/black_list.rules

echo "[+] Step 3: Deploying Custom local.rules..."
sudo cp rules/local.rules "${RULES_DIR}/local.rules"

echo "[+] Step 4: Validating Snort Configuration..."
sudo snort -T -c "${CONF_FILE}" -i "${INTERFACE}"

echo "[+] Step 5: Options for Execution:"
echo "    a) Run Snort Live Detection: sudo snort -A console -q -u snort -g snort -c ${CONF_FILE} -i ${INTERFACE}"
echo "    b) Analyze Baseline PCAP:   sudo snort -r baseline.pcap -c ${CONF_FILE}"
echo "    c) Analyze Attack PCAP:     sudo snort -r attack.pcap -c ${CONF_FILE} -l ${LOG_DIR}"

echo "[+] Script complete! Custom NIDS rules installed successfully."