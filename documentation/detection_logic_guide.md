# Snort Custom Detection Logic & Rule Engineering Documentation

This document provides technical explanations for each custom Snort rule created in `rules/local.rules`. It details the attack vectors, exact packet attributes targeted, MITRE ATT&CK mappings, and rationale for reliability.

---

### SID 1000001: Nmap ICMP Ping Sweep
- **Rule**: `alert icmp $EXTERNAL_NET any -> $HOME_NET any (msg:"NID-ENGINEERING: Nmap ICMP Ping Sweep Detected"; dsize:0; itype:8; classtype:network-scan; priority:3; sid:1000001; rev:1;)`
- **Vulnerability / Attack Vector**: Host Discovery / Reconnaissance (`nmap -sn`).
- **Packet Attributes**: ICMP Echo Request (`itype:8`) with payload data size equal to zero (`dsize:0`).
- **Reliability Rationale**: Standard OS ping utilities (Linux `ping`, Windows `ping`) send payload data (e.g., 32 or 56 bytes of alphanumeric characters or timestamps). Nmap ping sweeps by default send zero payload data bytes, making `dsize:0` a high-fidelity signature for automated discovery.

---

### SID 1000002: SSH Brute Force Authentication Attempt
- **Rule**: `alert tcp $EXTERNAL_NET any -> $HOME_NET 22 (msg:"NID-ENGINEERING: SSH Brute Force Connection Attempt"; flow:to_server,established; content:"SSH-2.0-"; fast_pattern; classtype:attempted-recon; priority:2; sid:1000002; rev:1;)`
- **Vulnerability / Attack Vector**: Password guessing / Brute forcing against SSH service (`auxiliary/scanner/ssh/ssh_login`).
- **Packet Attributes**: Established TCP stream (`flow:to_server,established`) on destination port 22 containing `SSH-2.0-`.
- **Reliability Rationale**: Target port restriction prevents inspection of unrelated traffic. Filtering for established connections prevents matching incomplete handshakes.

---

### SID 1000003: FTP Brute Force Failure Response
- **Rule**: `alert tcp $HOME_NET 21 -> $EXTERNAL_NET any (msg:"NID-ENGINEERING: FTP Authentication Failure (Possible Brute Force)"; flow:from_server,established; content:"530 Login incorrect"; fast_pattern; classtype:unsuccessful-user; priority:3; sid:1000003; rev:1;)`
- **Vulnerability / Attack Vector**: FTP password brute forcing (`auxiliary/scanner/ftp/ftp_login`).
- **Packet Attributes**: TCP response from local FTP server on port 21 containing RFC 959 error string `530 Login incorrect`.
- **Reliability Rationale**: Monitoring server responses (`from_server`) rather than client attempts guarantees accurate detection of failed login events without needing to parse multi-variate client credentials.

---

### SID 1000004: TCP SYN Flood Attack
- **Rule**: `alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"NID-ENGINEERING: TCP SYN Flood Attack Attempt"; flags:S; flow:stateless; classtype:attempted-dos; priority:1; sid:1000004; rev:1;)`
- **Vulnerability / Attack Vector**: Layer 4 Denial of Service (`hping3 -S --flood`).
- **Packet Attributes**: TCP SYN flag set without ACK flag (`flags:S`) with `flow:stateless` processing.
- **Reliability Rationale**: SYN floods attempt to exhaust server backlog buffers using unacknowledged connection requests. Setting `flow:stateless` ensures Snort inspects raw connection setup attempts even under resource exhaustion.

---

### SID 1000005: Metasploit Reverse HTTP Meterpreter Stager
- **Rule**: `alert tcp $EXTERNAL_NET any -> $HOME_NET 80,8080,4444 (msg:"NID-ENGINEERING: Metasploit HTTP Meterpreter Stager URI Request"; flow:to_server,established; content:"GET"; http_method; content:"/INITM"; fast_pattern; classtype:web-application-activity; priority:1; sid:1000005; rev:1;)`
- **Vulnerability / Attack Vector**: Metasploit Meterpreter C2 Stager delivery (`meterpreter/reverse_http`).
- **Packet Attributes**: HTTP `GET` request matching default Metasploit URI stager header patterns (`/INITM`).
- **Reliability Rationale**: Metasploit HTTP stagers use deterministic checksum-based URI patterns for stage payload retrieval. Matching HTTP method and URI prevents false positives from body text.

---

### SID 1000006: Nmap TCP SYN Stealth Scan
- **Rule**: `alert tcp $EXTERNAL_NET any -> $HOME_NET any (msg:"NID-ENGINEERING: Nmap TCP Stealth SYN Scan Detected"; flags:S; window:1024; classtype:network-scan; priority:3; sid:1000006; rev:1;)`
- **Vulnerability / Attack Vector**: Stealth Port Scanning (`nmap -sS`).
- **Packet Attributes**: TCP SYN packet with TCP Window Size set to exactly `1024` or `2048`.
- **Reliability Rationale**: Standard operating systems set TCP initial window sizes to 64240 (Linux), 65535 (Windows), or 65483. Nmap's raw SYN scan engine hardcodes fixed window sizes (1024/2048), forming an empirical fingerprint.

---

### SID 1000007: VSFTPD v2.3.4 Backdoor Trigger
- **Rule**: `alert tcp $EXTERNAL_NET any -> $HOME_NET 21 (msg:"NID-ENGINEERING: VSFTPD v2.3.4 Backdoor Trigger Attempt"; flow:to_server,established; content:"USER "; nocase; content:":)"; distance:0; fast_pattern; classtype:attempted-admin; priority:1; sid:1000007; rev:1;)`
- **Vulnerability / Attack Vector**: Remote Code Execution via VSFTPD 2.3.4 Backdoor (`exploit/unix/ftp/vsftpd_234_backdoor`).
- **Packet Attributes**: FTP `USER` command containing smiley face sequence `:)`.
- **Reliability Rationale**: The malicious code added to vsftpd-2.3.4.tar.gz opens a root shell on port 6200 whenever a username ending in `:)` is supplied. This exact sequence is specific to this exploit.

---

### SID 1000008: Samba trans2open Buffer Overflow
- **Rule**: `alert tcp $EXTERNAL_NET any -> $HOME_NET 139,445 (msg:"NID-ENGINEERING: Samba trans2open Buffer Overflow Payload"; flow:to_server,established; content:"|90 90 90 90 90 90 90 90 90 90|"; fast_pattern; classtype:attempted-admin; priority:1; sid:1000008; rev:1;)`
- **Vulnerability / Attack Vector**: Remote Command Execution in Samba (`exploit/linux/samba/trans2open`).
- **Packet Attributes**: SMB traffic on ports 139/445 containing a NOP sled sequence of 10 consecutive `0x90` bytes.
- **Reliability Rationale**: Standard SMB traffic consists of binary structure headers and string paths; consecutive NOP instructions indicate shellcode landing pads.

---

### SID 1000009: HTTP GET SQL Injection
- **Rule**: `alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"NID-ENGINEERING: HTTP GET SQL Injection Attempt"; flow:to_server,established; content:"GET"; http_method; content:"' OR "; nocase; fast_pattern; classtype:web-application-attack; priority:2; sid:1000009; rev:1;)`
- **Vulnerability / Attack Vector**: Web Application SQL Injection (`T1190`).
- **Packet Attributes**: HTTP `GET` request containing URL-encoded or raw SQL boolean bypass syntax `' OR `.
- **Reliability Rationale**: Restricting inspection to `http_method` and `http_uri` prevents matching static file paths or normal content.

---

### SID 1000010: HTTP Directory Traversal
- **Rule**: `alert tcp $EXTERNAL_NET any -> $HOME_NET 80 (msg:"NID-ENGINEERING: HTTP Directory Traversal Attempt"; flow:to_server,established; content:"../.."; fast_pattern; http_uri; classtype:web-application-attack; priority:2; sid:1000010; rev:1;)`
- **Vulnerability / Attack Vector**: Path Traversal / Arbitrary File Read (`T1083`).
- **Packet Attributes**: HTTP URI parameter containing repeated parent directory specifiers `../..`.
- **Reliability Rationale**: Standard web routing does not expose relative path resolution operators in URIs to end clients.
