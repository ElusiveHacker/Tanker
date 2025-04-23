#!/bin/bash

# Define services in format: name:port:protocol:plugin1,plugin2
SERVICES=(
    "telnet:23:TCP:telnet-ntlm-info"
    "ssh:22:TCP:ssh2-enum-algos"
    "msrpc:135:TCP:msrpc-enum"
    "nbstat:137:UDP:nbstat"
    "ldap:389:TCP:ldap-rootdse"
    "http:80:TCP:http-headers"
    "ssl:443:TCP:ssl-enum-ciphers"
    "wsman:5985:TCP:http-headers"
    "mssql:1433:TCP:ms-sql-info,ms-sql-dac,ms-sql-ntlm-info"
    "nfs:2049:UDP:nfs-ls,nfs-showmount,nfs-statfs"
    "mysql:3306:TCP:mysql-empty-password,mysql-enum,mysql-variables"
    "postgresql:5432:TCP:pgsql-brute"
    "oracle:1521:TCP:oracle-tns-version"
    "rpcbind:111:TCP:rpc-grind"
    "finger:79:TCP:fingerprint-strings"
    "rexec:512:TCP:rexec-brute"
    "vnc:5900:TCP:vnc-brute,vnc-title,realvnc-auth-bypass"
    "snmp:161:UDP:snmp-sysdescr"
    "smb:445:TCP:smb-enum-shares,smb-enum-users,smb-protocols"
)

# Check for missing scripts in nmap and skip tests
check_nmap_scripts() {
    local scripts="$1"
    IFS=',' read -r -a script_array <<< "$scripts"
    for script in "${script_array[@]}"; do
        if ! nmap --script="$script" --version >/dev/null 2>&1; then
            echo -e "[!] Warning: Nmap script '$script' not found. Skipping." | tee -a "$REPORT_FILE"
            return 1
        fi
    done
    return 0
}

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

# Function to generate IPs from CIDR
get_ips_from_cidr() {
    local cidr="$1"
    if [[ $cidr =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
        # Use nmap to list IPs in CIDR range
        nmap -sL -n "$cidr" | grep "Nmap scan report for" | awk '{print $5}'
    else
        # Single IP, return as-is
        echo "$cidr"
    fi
}

# Ensure nmap is installed
command -v nmap >/dev/null 2>&1 || { echo -e "Error: nmap is not installed."; exit 1; }

# Ensure enum4linux is installed
command -v enum4linux >/dev/null 2>&1 || { echo -e "Error: enum4linux is not installed."; exit 1; }

# Ask for target input
read -rp "Enter an IP address or CIDR range: " TARGET

# Validate input format
if ! validate_ip_or_cidr "$TARGET"; then
    echo -e "Invalid IP address or range format."
    exit 1
fi

# Track start time
START_TIME=$(date +%s)
START_HUMAN=$(date "+%Y-%m-%d %H:%M:%S")
TIMESTAMP=$(date "+%Y-%m-%d_%H-%M-%S")

# Create report file with timestamp
REPORT_FILE="${TIMESTAMP}_scan_report.txt"
> "$REPORT_FILE"

echo -e "------------------------------------------------"
echo -e "[*] Starting scan on $TARGET at $START_HUMAN" | tee -a "$REPORT_FILE"

# Get list of IPs to scan
IPS=($(get_ips_from_cidr "$TARGET"))

# Scan each IP
for ip in "${IPS[@]}"; do
    echo -e "\n[*] Scanning IP: $ip" | tee -a "$REPORT_FILE"

    # Scan each service individually, only if port is open
    for service in "${SERVICES[@]}"; do
        IFS=':' read -r name port proto scripts <<< "$service"
        echo -e "\n[*] Checking $name ($proto port $port) on $ip..." | tee -a "$REPORT_FILE"

        # Basic port check
        if [[ $proto == "TCP" ]]; then
            scan_output=$(nmap -Pn -p "$port" --open "$ip" -oG - 2>/dev/null)
        elif [[ $proto == "UDP" ]]; then
            scan_output=$(nmap -sU -Pn -p "$port" --open "$ip" -oG - 2>/dev/null)
        else
            echo -e "[!] Unknown protocol: $proto for $name" | tee -a "$REPORT_FILE"
            continue
        fi

        # Check if port is open
        if echo "$scan_output" | grep -q "Ports:.*open"; then
            echo -e "[+] $name port $port is open on $ip." | tee -a "$REPORT_FILE"
            if [[ -n "$scripts" ]]; then
                if check_nmap_scripts "$scripts"; then
                    echo -e "Running Nmap scripts: $scripts" | tee -a "$REPORT_FILE"
                    echo -e "----- Nmap Plugin Output for $name -----" | tee -a "$REPORT_FILE"
                    if [[ $proto == "TCP" ]]; then
                        nmap -n -sSV -p "$port" --min-rate=1000 --script "$scripts" "$ip" --open -oN temp_result.txt >/dev/null
                    else
                        nmap -n -sUV -p "$port" --min-rate=1000 --script "$scripts" "$ip" --open -oN temp_result.txt >/dev/null
                    fi
                    cat temp_result.txt | tee -a "$REPORT_FILE"
                else
                    echo -e "Skipping Nmap script execution due to missing scripts." | tee -a "$REPORT_FILE"
                fi
            else
                echo -e "No Nmap scripts specified. Running version scan only." | tee -a "$REPORT_FILE"
                echo -e "----- Nmap Plugin Output for $name -----" | tee -a "$REPORT_FILE"
                if [[ $proto == "TCP" ]]; then
                    nmap -n -sSV -p "$port" --min-rate=1000 "$ip" -oN temp_result.txt >/dev/null
                else
                    nmap -n -sUV -p "$port" --min-rate=1000 "$ip" -oN temp_result.txt >/dev/null
                fi
                cat temp_result.txt | tee -a "$REPORT_FILE"
            fi

            # Run enum4linux for SMB (port 445) if open
            if [[ "$port" == "445" && "$proto" == "TCP" ]]; then
                echo -e "Running enum4linux -a for SMB enumeration on $ip..." | tee -a "$REPORT_FILE"
                echo -e "----- enum4linux Output for $name -----" | tee -a "$REPORT_FILE"
                enum4linux -a "$ip" > temp_enum4linux.txt 2>&1
                cat temp_enum4linux.txt | tee -a "$REPORT_FILE"
            fi
        else
            echo -e "[-] $name port $port is closed or filtered on $ip. Skipping." | tee -a "$REPORT_FILE"
        fi
    done
done

# Track end time
END_TIME=$(date +%s)
END_HUMAN=$(date "+%Y-%m-%d %H:%M:%S")
DURATION=$((END_TIME - START_TIME))

# Clean up
rm -f temp_result.txt temp_enum4linux.txt

echo -e "\n[*] Scan complete at $END_HUMAN. Duration: ${DURATION} seconds" | tee -a "$REPORT_FILE"
echo "========== Summary ==========" | tee -a "$REPORT_FILE"
echo "Target: $TARGET" | tee -a "$REPORT_FILE"
grep -E "^[0-9]+/(tcp|udp)" "$REPORT_FILE" | sort -u | tee -a "$REPORT_FILE"
echo "=============================" | tee -a "$REPORT_FILE"

# Add duration to the report file
{
    echo ""
    echo "========== Scan Metadata =========="
    echo "Started at: $START_HUMAN"
    echo "Finished at: $END_HUMAN"
    echo "Total Duration: ${DURATION} seconds"
    echo "==================================="
} >> "$REPORT_FILE"
