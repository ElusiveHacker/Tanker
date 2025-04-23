# 🔍 Multi-Service Nmap Scanner

A Bash script to automate targeted service enumeration on specific ports using **Nmap** and **enum4linux**. Designed for penetration testers and sysadmins who want a streamlined method to scan common services across IP ranges with tailored Nmap plugin execution.

---

## 📦 Features

- Scans predefined services and ports (e.g., SSH, SMB, MSSQL, etc.)
- Supports both **TCP** and **UDP** protocols
- Auto-validates target input (IP or CIDR format)
- Executes specific **Nmap scripts** per service
- Uses `enum4linux` for extended SMB enumeration
- Generates a detailed, timestamped report
- Skips missing Nmap scripts gracefully with warnings

---

## 🛠️ Requirements

- `bash`
- [`nmap`](https://nmap.org/)
- [`enum4linux`](https://tools.kali.org/information-gathering/enum4linux)

Ensure both `nmap` and `enum4linux` are installed and in your system `PATH`.

---

## 🚀 Usage

```bash
chmod +x multi-service-scanner.sh
./multi-service-scanner.sh
