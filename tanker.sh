#!/bin/bash

# Define colors
YELLOW='\033[1;33m'
BLUE='\033[1;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Define services in format: name:port:protocol:plugin1,plugin2
SERVICES=(
    "telnet:23:TCP:telnet-ntlm-info"
    "ssh:22:TCP:ssh2-enum-algos"
    "msrpc:135:TCP:msrpc-enum"
    "nbstat:137:TCP:nbstat"
    "ldap:389:TCP:ldap-rootdse"
    "http:80:TCP:http-headers"
    "smtp:25:TCP:smtp-open-relay,smtp-strangeport"
    "wsman:5985:TCP:http-headers"
)

# Validate IP or CIDR notation
validate_ip_or_cidr() {
    local input="$1"
    if [[ $input =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || [[ $input =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        IFS='/' read -r ip mask <<< "$input"
        IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
        for octet in $o1 $o2 $o3 $o4; do
            [[ "$octet" -ge 0 && "$octet" -le 255 ]] || return 1
        done
        [[ -z "$mask" || ( "$mask" -ge 0 && "$mask" -le 32 ) ]] || return 1
        return 0
    fi
    return 1
}

# Ensure nmap is installed
command -v nmap >/dev/null 2>&1 || { echo -e "${RED}Error: nmap is not installed.${NC}"; exit 1; }

# Ask for target input
read -rp "Enter an IP address or CIDR range: " TARGET

# Validate input format
if ! validate_ip_or_cidr "$TARGET"; then
    echo -e "${RED}Invalid IP address or range format.${NC}"
    exit 1
fi

# Track start time
START_TIME=$(date +%s)
START_HUMAN=$(date "+%Y-%m-%d %H:%M:%S")

# Create report file
REPORT_FILE="scan_report.txt"
> "$REPORT_FILE"

echo -e "${YELLOW}[*] Starting scan on $TARGET at $START_HUMAN${NC}" | tee -a "$REPORT_FILE"

# Scan each service individually, only if port is open
for service in "${SERVICES[@]}"; do
    IFS=':' read -r name port proto scripts <<< "$service"
    echo -e "\n[*] Checking $name ($proto port $port)..." | tee -a "$REPORT_FILE"

    # Basic port check
    if [[ $proto == "TCP" ]]; then
        scan_output=$(nmap -Pn -p "$port" --open "$TARGET" -oG - 2>/dev/null)
    elif [[ $proto == "UDP" ]]; then
        scan_output=$(nmap -sU -Pn -p "$port" --open "$TARGET" -oG - 2>/dev/null)
    else
        echo -e "${RED}[!] Unknown protocol: $proto for $name${NC}" | tee -a "$REPORT_FILE"
        continue
    fi

    # Check if port is open
    if echo "$scan_output" | grep -q "Ports:.*open"; then
        echo -e "${YELLOW}[+] $name port $port is open. Running scripts: $scripts${NC}" | tee -a "$REPORT_FILE"
        if [[ $proto == "TCP" ]]; then
            nmap -sSV -p "$port" --script "$scripts" "$TARGET" -oN temp_result.txt
        else
            nmap -sUV -p "$port" --script "$scripts" "$TARGET" -oN temp_result.txt
        fi
        # Print plugin output in red
        echo -e "${RED}----- Plugin Output for $name -----${NC}"
        cat temp_result.txt | tee -a "$REPORT_FILE" | sed "s/^/${RED}/" | sed "s/$/${NC}/"
    else
        echo -e "${BLUE}[-] $name port $port is closed or filtered. Skipping.${NC}" | tee -a "$REPORT_FILE"
    fi
done

# Track end time
END_TIME=$(date +%s)
END_HUMAN=$(date "+%Y-%m-%d %H:%M:%S")
DURATION=$((END_TIME - START_TIME))

# Clean up
rm -f temp_result.txt

echo -e "\n${YELLOW}[*] Scan complete at $END_HUMAN. Duration: ${DURATION} seconds${NC}"
echo "========== Summary =========="
grep -E "^Nmap scan report for|^[0-9]+/(tcp|udp)" "$REPORT_FILE"
echo "============================="

# Add duration to the report file
{
    echo ""
    echo "========== Scan Metadata =========="
    echo "Started at: $START_HUMAN"
    echo "Finished at: $END_HUMAN"
    echo "Total Duration: ${DURATION} seconds"
    echo "==================================="
} >> "$REPORT_FILE"
