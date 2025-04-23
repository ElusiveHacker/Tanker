# 🔍 Advanced Nmap Service Scanner

This Bash script performs targeted network service scans using **Nmap**, based on a predefined list of services and their associated ports and plugins. It supports TCP/UDP scanning, displays results with color-coded terminal output, logs open/closed services, and generates a detailed scan report with timestamps and duration.

## 🚀 Features

- ✅ Scans only **open** ports (fast and efficient).
- 📜 Uses **Nmap plugins/scripts** for deeper analysis of each service.
- 🎨 **Color-coded** terminal output:
  - 🟡 Yellow for open ports
  - 🔵 Blue for closed/filtered ports
- 📅 **Start and end time** displayed in terminal and stored in report.
- 🕒 **Total duration** included in report summary.
- 🗂️ Generates a full scan report in `scan_report.txt`.

## ⚙️ Prerequisites

- `bash`
- [`nmap`](https://nmap.org/) installed and available in `$PATH`

## 📦 Services Scanned

The script currently scans the following services:

| Service | Port | Protocol | Nmap Script(s)              |
|---------|------|----------|-----------------------------|
| telnet  | 23   | TCP      | telnet-ntlm-info            |
| ssh     | 22   | TCP      | ssh2-enum-algos             |
| msrpc   | 135  | TCP      | msrpc-enum                  |
| nbstat  | 137  | TCP      | nbstat                      |
| ldap    | 389  | TCP      | ldap-rootdse                |
| http    | 80   | TCP      | http-headers                |
| smtp    | 25   | TCP      | smtp-open-relay, smtp-strangeport |
| wsman   | 5985 | TCP      | http-headers                |

You can easily modify or extend this list in the `SERVICES` array in the script.

## 🛠️ Usage

```bash
chmod +x nmap_service_scanner.sh
./tanker.sh
