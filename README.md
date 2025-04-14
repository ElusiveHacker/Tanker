# Tanker
This is a CTF tool used to scan CTF active directory challenges.

# Network Security Scanner Tanker

A Bash script for automated network security scanning and enumeration. It accepts a single IP or CIDR range, validates input, and uses various tools to scan and enumerate specified services, generating a detailed, searchable report.

## Features

- **Input Validation**: Accepts one IP or CIDR range, with error handling for invalid formats.
- **Tool Checking**: Verifies required tools (`nmap`, `smbclient`, etc.) and skips unavailable ones.
- **Scans Performed**:
  - **Nmap**: Ping scan to identify live hosts, followed by TCP/UDP scans with service-specific plugins (e.g., `ftp-anon`, `http*`) for enumeration.
  - **SMB**: Tests null sessions and guest accounts using `smbclient` and `smbmap`; runs `enum4linux -a` for detailed enumeration.
  - **Metasploit**: Identifies exploits based on service banners via `msfconsole`.
  - **SNMP**: Enumerates with `snmpwalk` (v1, community `public`).
  - **SMTP**: Enumerates users with `smtp-user-enum`.
  - **LDAP**: Queries directories using `ldapsearch`.
- **Services Scanned**: Includes Telnet (23/TCP), SSH (22/TCP), SNMP (161/UDP), HTTP (80/TCP), HTTPS (443/TCP), MySQL (3306/TCP), and more (see [Services](#services)).
- **Progress Tracking**: Real-time updates with host/service counts, percentages, and scan duration (e.g., "1/10 hosts (10%), 3/10 services (30%) | Elapsed: 00:01:23").
- **Reporting**: Generates a searchable report with one "Host: <IP>" header per host, separated by dashed lines, including all tool outputs.
- **Colorized Output**: Uses colors for clarity (red for errors, green for success, etc.).
- **Performance**: Optimized with efficient parsing, open-port checks, and sequential processing.

## Services

The script scans the following services (Cisco Reverse Telnet and rusers omitted due to non-standard ports):

- Telnet (23/TCP)
- SSH (22/TCP)
- SNMP (161/UDP)
- TFTP (69/UDP)
- NTP (123/UDP)
- Microsoft RPC (135/TCP,UDP)
- NetBIOS-ns (137/TCP,UDP)
- LDAP (389/TCP,UDP)
- VNC (5900/TCP, 5800/TCP over HTTP)
- X11 (6000/TCP, 6001/UDP)
- DHCP (67,68/UDP)
- rexec (512/TCP)
- rlogin (513/TCP)
- rwho (513/TCP,UDP)
- SMTP (25/TCP)
- finger (79/TCP)
- NFS (2049/UDP)
- HTTP (80/TCP)
- HTTPS (443/TCP)
- DNS (53/TCP,UDP)
- MySQL (3306/TCP)
- MSSQL (1433/TCP)
- PostgreSQL (5432/TCP)
- Oracle (1521/TCP)

## Prerequisites

- **Operating System**: Linux (tested on Debian-based systems).
- **Privileges**: Root access (required for UDP scans and some Nmap scripts).
- **Tools**:
  - `nmap`
  - `smbclient`
  - `smbmap`
  - `enum4linux`
  - `metasploit-framework`
  - `snmp`
  - `smtp-user-enum`
  - `ldap-utils`

## Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/<your-username>/network-security-scanner.git
   cd network-security-scanner
