#!/bin/bash

# ================================================================================================================================= #
# Linux Evidence Collection Script                                                                                                  #
# Version: 2.1                                                                                                                      #
# Status: UNTESTED                                                                                                                  #
# Description: Advanced incident response evidence collection script for Linux hosts                                                #                             #
#              Uses tools like AVML for memory capture and improved process enumeration                                             #                     #
# Requirements: Root privileges, AVML, Linux tools (ss, lsof, etc.)                                                                 #
# Usage: sudo ./linux_data_collection.sh /path/to/storage/device                                                                    #
# Note: This script is designed to work on RHEL and Ubuntu systems. It may have unexpected behaviour on other distributions.         #
# ================================================================================================================================= #

set -euo pipefail  # Exit on error, undefined vars, pipe failures

# Script configuration
readonly SCRIPT_VERSION="2.0"
readonly SCRIPT_NAME="linux_data_collection.sh"
readonly REQUIRED_BS="16k"  # Minimum block size for dd operations

# Color codes for output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m' # No Color

# Global variables
EVIDENCEPATH=""
LOGFILE=""
HASH_LOG=""
COLLECTION_START_TIME=""
HOSTNAME=""
SYSTEM_TYPE=""

# Function to print colored output
print_status() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case "$level" in
        "INFO")
            echo -e "${BLUE}[INFO]${NC} $message"
            echo "[INFO] $timestamp - $message" >> "$LOGFILE"
            ;;
        "SUCCESS")
            echo -e "${GREEN}[SUCCESS]${NC} $message"
            echo "[SUCCESS] $timestamp - $message" >> "$LOGFILE"
            ;;
        "WARNING")
            echo -e "${YELLOW}[WARNING]${NC} $message"
            echo "[WARNING] $timestamp - $message" >> "$LOGFILE"
            ;;
        "ERROR")
            echo -e "${RED}[ERROR]${NC} $message"
            echo "[ERROR] $timestamp - $message" >> "$LOGFILE"
            ;;
        "PROGRESS")
            echo -e "${BLUE}[PROGRESS]${NC} $message"
            echo "[PROGRESS] $timestamp - $message" >> "$LOGFILE"
            ;;
    esac
}

# Function to log hash information
log_hash() {
    local file_path="$1"
    local hash_type="$2"
    
    if [[ -f "$file_path" ]]; then
        case "$hash_type" in
            "md5")
                local hash=$(md5sum "$file_path" | cut -d' ' -f1)
                ;;
            "sha256")
                local hash=$(sha256sum "$file_path" | cut -d' ' -f1)
                ;;
            *)
                local hash=$(sha256sum "$file_path" | cut -d' ' -f1)
                ;;
        esac
        
        echo "$(date '+%Y-%m-%d %H:%M:%S') - $hash_type:$hash - $file_path" >> "$HASH_LOG"
        print_status "INFO" "Hash ($hash_type): $hash - $file_path"
    else
        print_status "WARNING" "File not found for hashing: $file_path"
    fi
}

# Function to check if running on physical device being analyzed
check_physical_device() {
    local target_path="$1"
    local root_device=""
    
    # Get the root device
    if command -v lsblk >/dev/null 2>&1; then
        root_device=$(lsblk -no PKNAME "$(df / | tail -1 | awk '{print $1}')" 2>/dev/null || echo "")
    else
        root_device=$(df / | tail -1 | awk '{print $1}' | sed 's/[0-9]*$//')
    fi
    
    if [[ -n "$root_device" ]]; then
        # Check if target path is on the same device as root
        local target_device=""
        if [[ -d "$target_path" ]]; then
            target_device=$(df "$target_path" | tail -1 | awk '{print $1}' | sed 's/[0-9]*$//')
        fi
        
        if [[ "$target_device" == "$root_device" ]]; then
            print_status "ERROR" "Cannot write evidence to the same physical device being analyzed!"
            print_status "ERROR" "Root device: $root_device, Target device: $target_device"
            exit 1
        fi
    fi
}

# Function to check system type (RHEL vs Ubuntu)
detect_system_type() {
    if [[ -f /etc/redhat-release ]]; then
        SYSTEM_TYPE="RHEL"
        print_status "INFO" "Detected RHEL/CentOS system"
    elif [[ -f /etc/os-release ]] && grep -q "Ubuntu" /etc/os-release; then
        SYSTEM_TYPE="UBUNTU"
        print_status "INFO" "Detected Ubuntu system"
    else
        SYSTEM_TYPE="UNKNOWN"
        print_status "WARNING" "Unknown system type, some features may not work"
    fi
}

# Function to check and install required tools
check_requirements() {
    local missing_tools=()
    
    # Check for essential tools
    local essential_tools=("ss" "lsof" "ps" "netstat" "md5sum" "sha256sum")
    
    for tool in "${essential_tools[@]}"; do
        if ! command -v "$tool" >/dev/null 2>&1; then
            missing_tools+=("$tool")
        fi
    done
    
    # Check for AVML
    if ! command -v avml >/dev/null 2>&1; then
        print_status "WARNING" "AVML not found. Memory capture will be skipped."
        print_status "WARNING" "Install AVML for memory capture: https://github.com/microsoft/avml"
    fi
    
    # Check for ewfacquire
    if ! command -v ewfacquire >/dev/null 2>&1; then
        print_status "WARNING" "ewfacquire not found. Will use dd for disk imaging."
    fi
    
    if [[ ${#missing_tools[@]} -gt 0 ]]; then
        print_status "ERROR" "Missing required tools: ${missing_tools[*]}"
        exit 1
    fi
    
    print_status "SUCCESS" "All required tools are available"
}

# Function to collect system information
collect_system_info() {
    print_status "PROGRESS" "Collecting system information..."
    
    local sysinfo_file="$EVIDENCEPATH/system_information.txt"
    
    {
        echo "=== SYSTEM INFORMATION ==="
        echo "Collection Time: $(date)"
        echo "Hostname: $(hostname)"
        echo "System Type: $SYSTEM_TYPE"
        echo ""
        
        echo "=== KERNEL INFORMATION ==="
        uname -a
        echo ""
        
        echo "=== OS RELEASE ==="
        if [[ -f /etc/os-release ]]; then
            cat /etc/os-release
        elif [[ -f /etc/redhat-release ]]; then
            cat /etc/redhat-release
        fi
        echo ""
        
        echo "=== HARDWARE INFORMATION ==="
        if command -v dmidecode >/dev/null 2>&1; then
            echo "System Manufacturer: $(dmidecode -s system-manufacturer 2>/dev/null || echo "N/A")"
            echo "System Product: $(dmidecode -s system-product-name 2>/dev/null || echo "N/A")"
            echo "System Version: $(dmidecode -s system-version 2>/dev/null || echo "N/A")"
            echo "System Serial: $(dmidecode -s system-serial-number 2>/dev/null || echo "N/A")"
            echo "System UUID: $(dmidecode -s system-uuid 2>/dev/null || echo "N/A")"
        fi
        echo ""
        
        echo "=== ENVIRONMENT VARIABLES ==="
        printenv | sort
        echo ""
        
        echo "=== MOUNT POINTS ==="
        mount | sort
        echo ""
        
        echo "=== DISK USAGE ==="
        df -h
        echo ""
        
        echo "=== USB DEVICES ==="
        if command -v lsusb >/dev/null 2>&1; then
            lsusb
        fi
        echo ""
        
        echo "=== PCI DEVICES ==="
        if command -v lspci >/dev/null 2>&1; then
            lspci
        fi
        echo ""
        
        echo "=== LOADED KERNEL MODULES ==="
        lsmod | head -20
        echo ""
        
        echo "=== SYSTEM UPTIME ==="
        uptime
        echo ""
        
        echo "=== CURRENT TIME ==="
        date
        echo ""
        
        echo "=== TIMEZONE ==="
        if [[ -f /etc/timezone ]]; then
            cat /etc/timezone
        fi
        echo ""
        
    } > "$sysinfo_file"
    
    log_hash "$sysinfo_file" "sha256"
    print_status "SUCCESS" "System information collected: $sysinfo_file"
}

# Function to collect process information
collect_process_info() {
    print_status "PROGRESS" "Collecting process information..."
    
    local proc_dir="$EVIDENCEPATH/process_information"
    mkdir -p "$proc_dir"
    
    # Collect running processes with ps
    local ps_file="$proc_dir/running_processes_ps.txt"
    ps auxww > "$ps_file" 2>/dev/null || ps aux > "$ps_file"
    log_hash "$ps_file" "sha256"
    
    # Collect process tree
    local pstree_file="$proc_dir/process_tree.txt"
    if command -v pstree >/dev/null 2>&1; then
        pstree -pa > "$pstree_file" 2>/dev/null || echo "pstree failed" > "$pstree_file"
    else
        echo "pstree not available" > "$pstree_file"
    fi
    log_hash "$pstree_file" "sha256"
    
    # Collect process information from /proc without copying entire directory
    local proc_info_file="$proc_dir/proc_process_info.txt"
    {
        echo "=== PROCESS INFORMATION FROM /PROC ==="
        echo "Collection Time: $(date)"
        echo ""
        
        echo "=== RUNNING PROCESSES (PID LIST) ==="
        ls -la /proc/ | grep '^d' | grep -E '^d.*[0-9]+$' | awk '{print $9}' | sort -n
        echo ""
        
        echo "=== PROCESS STATISTICS ==="
        echo "Total processes: $(ls -d /proc/[0-9]* 2>/dev/null | wc -l)"
        echo ""
        
        echo "=== PROCESS COMMAND LINES ==="
        for pid in $(ls -d /proc/[0-9]* 2>/dev/null | awk -F'/' '{print $3}' | sort -n); do
            if [[ -r "/proc/$pid/cmdline" ]]; then
                local cmdline=$(cat "/proc/$pid/cmdline" 2>/dev/null | tr '\0' ' ')
                if [[ -n "$cmdline" ]]; then
                    echo "PID: $pid - CMD: $cmdline"
                fi
            fi
        done | head -100  # Limit output to prevent excessive size
        echo ""
        
        echo "=== PROCESS ENVIRONMENT SAMPLES ==="
        # Sample a few processes for environment info
        local count=0
        for pid in $(ls -d /proc/[0-9]* 2>/dev/null | awk -F'/' '{print $3}' | sort -n); do
            if [[ $count -lt 5 ]] && [[ -r "/proc/$pid/environ" ]]; then
                echo "PID: $pid Environment:"
                cat "/proc/$pid/environ" 2>/dev/null | tr '\0' '\n' | head -10
                echo "---"
                ((count++))
            fi
        done
        
    } > "$proc_info_file"
    
    log_hash "$proc_info_file" "sha256"
    
    # Collect specific process details for suspicious processes
    local suspicious_procs_file="$proc_dir/suspicious_processes.txt"
    {
        echo "=== POTENTIALLY SUSPICIOUS PROCESSES ==="
        echo "Collection Time: $(date)"
        echo ""
        
        echo "=== PROCESSES WITH NO TTY ==="
        ps aux | grep -v "\[" | grep -v "TTY" | grep -v "pts" | head -20
        echo ""
        
        echo "=== PROCESSES WITH HIGH CPU/MEMORY ==="
        ps aux --sort=-%cpu | head -10
        echo ""
        ps aux --sort=-%mem | head -10
        echo ""
        
        echo "=== PROCESSES STARTED RECENTLY ==="
        ps -eo pid,lstart,cmd | head -20
        echo ""
        
    } > "$suspicious_procs_file"
    
    log_hash "$suspicious_procs_file" "sha256"
    print_status "SUCCESS" "Process information collected in: $proc_dir"
}

# Function to collect network information
collect_network_info() {
    print_status "PROGRESS" "Collecting network information..."
    
    local net_dir="$EVIDENCEPATH/network_information"
    mkdir -p "$net_dir"
    
    # Network connections using ss (modern replacement for netstat)
    local ss_file="$net_dir/network_connections_ss.txt"
    ss -tulnpa > "$ss_file" 2>/dev/null || ss -tuln > "$ss_file"
    log_hash "$ss_file" "sha256"
    
    # Network connections using lsof
    local lsof_net_file="$net_dir/network_connections_lsof.txt"
    lsof -i -P -n > "$lsof_net_file" 2>/dev/null || echo "lsof network info failed" > "$lsof_net_file"
    log_hash "$lsof_net_file" "sha256"
    
    # ARP cache
    local arp_file="$net_dir/arp_cache.txt"
    ip neigh show > "$arp_file" 2>/dev/null || arp -a > "$arp_file" 2>/dev/null || echo "ARP info not available" > "$arp_file"
    log_hash "$arp_file" "sha256"
    
    # Routing table
    local route_file="$net_dir/routing_table.txt"
    ip route show > "$route_file" 2>/dev/null || route -n > "$route_file" 2>/dev/null || echo "Routing info not available" > "$route_file"
    log_hash "$route_file" "sha256"
    
    # Network interfaces
    local interfaces_file="$net_dir/network_interfaces.txt"
    ip addr show > "$interfaces_file" 2>/dev/null || ifconfig -a > "$interfaces_file" 2>/dev/null || echo "Interface info not available" > "$interfaces_file"
    log_hash "$interfaces_file" "sha256"
    
    # DNS configuration
    local dns_file="$net_dir/dns_configuration.txt"
    {
        echo "=== DNS CONFIGURATION ==="
        echo "Collection Time: $(date)"
        echo ""
        
        if [[ -f /etc/resolv.conf ]]; then
            echo "=== /etc/resolv.conf ==="
            cat /etc/resolv.conf
            echo ""
        fi
        
        if [[ -f /etc/hosts ]]; then
            echo "=== /etc/hosts ==="
            cat /etc/hosts
            echo ""
        fi
        
        echo "=== ACTIVE DNS QUERIES ==="
        if command -v nslookup >/dev/null 2>&1; then
            nslookup google.com 2>/dev/null | head -10 || echo "nslookup failed"
        fi
        
    } > "$dns_file"
    
    log_hash "$dns_file" "sha256"
    print_status "SUCCESS" "Network information collected in: $net_dir"
}

# Function to collect user history files
collect_user_history() {
    print_status "PROGRESS" "Collecting user history files..."
    
    local history_dir="$EVIDENCEPATH/user_history"
    mkdir -p "$history_dir"
    
    # Get all users with shells
    local users=$(getent passwd | grep -E '/(bash|sh|zsh|fish)$' | cut -d: -f1 | sort | uniq)
    
    for user in $users; do
        local user_dir="$history_dir/$user"
        mkdir -p "$user_dir"
        
        # Bash history
        if [[ -f "/home/$user/.bash_history" ]]; then
            cp "/home/$user/.bash_history" "$user_dir/bash_history.txt" 2>/dev/null || echo "Failed to copy bash history" > "$user_dir/bash_history.txt"
            log_hash "$user_dir/bash_history.txt" "sha256"
        fi
        
        # Zsh history
        if [[ -f "/home/$user/.zsh_history" ]]; then
            cp "/home/$user/.zsh_history" "$user_dir/zsh_history.txt" 2>/dev/null || echo "Failed to copy zsh history" > "$user_dir/zsh_history.txt"
            log_hash "$user_dir/zsh_history.txt" "sha256"
        fi
        
        # Fish history
        if [[ -f "/home/$user/.local/share/fish/fish_history" ]]; then
            cp "/home/$user/.local/share/fish/fish_history" "$user_dir/fish_history.txt" 2>/dev/null || echo "Failed to copy fish history" > "$user_dir/fish_history.txt"
            log_hash "$user_dir/fish_history.txt" "sha256"
        fi
        
        # SSH known hosts
        if [[ -f "/home/$user/.ssh/known_hosts" ]]; then
            cp "/home/$user/.ssh/known_hosts" "$user_dir/ssh_known_hosts.txt" 2>/dev/null || echo "Failed to copy SSH known hosts" > "$user_dir/ssh_known_hosts.txt"
            log_hash "$user_dir/ssh_known_hosts.txt" "sha256"
        fi
        
        # SSH config
        if [[ -f "/home/$user/.ssh/config" ]]; then
            cp "/home/$user/.ssh/config" "$user_dir/ssh_config.txt" 2>/dev/null || echo "Failed to copy SSH config" > "$user_dir/ssh_config.txt"
            log_hash "$user_dir/ssh_config.txt" "sha256"
        fi
        
        # Check SSH private keys for password protection
        if [[ -d "/home/$user/.ssh" ]]; then
            local ssh_keys_file="$user_dir/ssh_private_keys_analysis.txt"
            echo "=== SSH PRIVATE KEY ANALYSIS FOR USER: $user ===" > "$ssh_keys_file"
            echo "Collection Time: $(date)" >> "$ssh_keys_file"
            echo "" >> "$ssh_keys_file"
            
            # Find all private key files
            local private_keys=$(find "/home/$user/.ssh" -type f -name "id_*" -not -name "*.pub" 2>/dev/null)
            
            if [[ -n "$private_keys" ]]; then
                echo "Found private keys:" >> "$ssh_keys_file"
                echo "" >> "$ssh_keys_file"
                
                for key_file in $private_keys; do
                    local key_name=$(basename "$key_file")
                    local key_hash=$(sha256sum "$key_file" 2>/dev/null | cut -d' ' -f1)
                    
                    echo "Key: $key_name" >> "$ssh_keys_file"
                    echo "Path: $key_file" >> "$ssh_keys_file"
                    echo "SHA256: $key_hash" >> "$ssh_keys_file"
                    
                    # Test if key has no password (suppress errors)
                    if ssh-keygen -y -f "$key_file" -P "" >/dev/null 2>&1; then
                        echo "Password Protection: NO PASSWORD SET - SECURITY RISK!" >> "$ssh_keys_file"
                        print_status "WARNING" "SSH key without password found: $key_file for user $user"
                        log_hash "$key_file" "sha256"
                    else
                        echo "Password Protection: PASSWORD SET (secure)" >> "$ssh_keys_file"
                        print_status "INFO" "SSH key with password found: $key_file for user $user"
                        log_hash "$key_file" "sha256"
                    fi
                    
                    echo "" >> "$ssh_keys_file"
                done
            else
                echo "No private SSH keys found." >> "$ssh_keys_file"
            fi
            
            log_hash "$ssh_keys_file" "sha256"
        fi
    done
    
    # Root user history (if different location)
    if [[ -f "/root/.bash_history" ]]; then
        local root_dir="$history_dir/root"
        mkdir -p "$root_dir"
        cp "/root/.bash_history" "$root_dir/bash_history.txt" 2>/dev/null || echo "Failed to copy root bash history" > "$root_dir/bash_history.txt"
        log_hash "$root_dir/bash_history.txt" "sha256"
    fi
    
    # Check root user SSH private keys for password protection
    if [[ -d "/root/.ssh" ]]; then
        local root_ssh_keys_file="$history_dir/root/ssh_private_keys_analysis.txt"
        echo "=== SSH PRIVATE KEY ANALYSIS FOR ROOT USER ===" > "$root_ssh_keys_file"
        echo "Collection Time: $(date)" >> "$root_ssh_keys_file"
        echo "" >> "$root_ssh_keys_file"
        
        # Find all private key files
        local root_private_keys=$(find "/root/.ssh" -type f -name "id_*" -not -name "*.pub" 2>/dev/null)
        
        if [[ -n "$root_private_keys" ]]; then
            echo "Found private keys:" >> "$root_ssh_keys_file"
            echo "" >> "$root_ssh_keys_file"
            
            for key_file in $root_private_keys; do
                local key_name=$(basename "$key_file")
                local key_hash=$(sha256sum "$key_file" 2>/dev/null | cut -d' ' -f1)
                
                echo "Key: $key_name" >> "$root_ssh_keys_file"
                echo "Path: $key_file" >> "$root_ssh_keys_file"
                echo "SHA256: $key_hash" >> "$root_ssh_keys_file"
                
                # Test if key has no password (suppress errors)
                if ssh-keygen -y -f "$key_file" -P "" >/dev/null 2>&1; then
                    echo "Password Protection: NO PASSWORD SET - SECURITY RISK!" >> "$root_ssh_keys_file"
                    print_status "WARNING" "SSH key without password found: $key_file for root user"
                    log_hash "$key_file" "sha256"
                else
                    echo "Password Protection: PASSWORD SET (secure)" >> "$root_ssh_keys_file"
                    print_status "INFO" "SSH key with password found: $key_file for root user"
                    log_hash "$key_file" "sha256"
                fi
                
                echo "" >> "$root_ssh_keys_file"
            done
        else
            echo "No private SSH keys found." >> "$root_ssh_keys_file"
        fi
        
        log_hash "$root_ssh_keys_file" "sha256"
    fi
    
    print_status "SUCCESS" "User history files collected in: $history_dir"
}

# Function to collect log files
collect_log_files() {
    print_status "PROGRESS" "Collecting log files..."
    
    local logs_dir="$EVIDENCEPATH/system_logs"
    mkdir -p "$logs_dir"
    
    # Common log locations
    local log_locations=(
        "/var/log/auth.log"
        "/var/log/secure"
        "/var/log/messages"
        "/var/log/syslog"
        "/var/log/kern.log"
        "/var/log/dmesg"
        "/var/log/audit/audit.log"
        "/var/log/btmp"
        "/var/log/wtmp"
        "/var/log/lastlog"
        "/var/log/faillog"
    )
    
    for log_file in "${log_locations[@]}"; do
        if [[ -f "$log_file" ]]; then
            local filename=$(basename "$log_file")
            local target_file="$logs_dir/$filename"
            
            # For large log files, only copy recent entries
            if [[ "$filename" == "messages" ]] || [[ "$filename" == "syslog" ]]; then
                tail -1000 "$log_file" > "$target_file" 2>/dev/null || echo "Failed to copy $log_file" > "$target_file"
            else
                cp "$log_file" "$target_file" 2>/dev/null || echo "Failed to copy $log_file" > "$target_file"
            fi
            
            log_hash "$target_file" "sha256"
        fi
    done
    
    # Collect journalctl logs if available
    if command -v journalctl >/dev/null 2>&1; then
        local journal_file="$logs_dir/journalctl_recent.txt"
        journalctl --since "24 hours ago" --no-pager > "$journal_file" 2>/dev/null || echo "journalctl failed" > "$journal_file"
        log_hash "$journal_file" "sha256"
    fi
    
    # Collect audit logs if auditd is running
    if command -v ausearch >/dev/null 2>&1; then
        local audit_file="$logs_dir/audit_events.txt"
        ausearch -ts today > "$audit_file" 2>/dev/null || echo "ausearch failed" > "$audit_file"
        log_hash "$audit_file" "sha256"
    fi
    
    print_status "SUCCESS" "Log files collected in: $logs_dir"
}

# Function to identify recently modified executables
collect_recent_executables() {
    print_status "PROGRESS" "Identifying recently modified executables..."
    
    local exec_file="$EVIDENCEPATH/recent_executables.txt"
    local five_days_ago=$(date -d "5 days ago" +%s 2>/dev/null || echo "0")
    
    {
        echo "=== RECENTLY MODIFIED EXECUTABLES (Last 5 Days) ==="
        echo "Collection Time: $(date)"
        echo "Search Time: 5 days ago from collection"
        echo "Format: MD5_HASH | FILE_PATH | MODIFICATION_TIME"
        echo ""
        
        # Find executables modified in last 5 days
        find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin /opt /home /root -type f -executable -mtime -5 2>/dev/null | while read -r file; do
            if [[ -f "$file" ]] && [[ -r "$file" ]]; then
                local hash=$(md5sum "$file" 2>/dev/null | cut -d' ' -f1)
                local mtime=$(stat -c %y "$file" 2>/dev/null || echo "N/A")
                echo "$hash | $file | $mtime"
            fi
        done | head -1000  # Limit to prevent excessive output
        
    } > "$exec_file"
    
    log_hash "$exec_file" "sha256"
    print_status "SUCCESS" "Recent executables list created: $exec_file"
}

# Function to capture memory using AVML
capture_memory() {
    if ! command -v avml >/dev/null 2>&1; then
        print_status "WARNING" "AVML not available, skipping memory capture"
        return
    fi
    
    print_status "PROGRESS" "Starting memory capture with AVML..."
    
    local memory_file="$EVIDENCEPATH/memory_dump.raw"
    
    # Notify user about long process
    print_status "WARNING" "Memory capture will take several minutes depending on RAM size"
    print_status "WARNING" "Press Ctrl+C within 2 seconds to skip memory capture..."
    sleep 2
    
    print_status "INFO" "Memory capture started at $(date)"
    print_status "INFO" "Output file: $memory_file"
    
    # Capture memory with AVML
    if avml "$memory_file"; then
        log_hash "$memory_file" "sha256"
        print_status "SUCCESS" "Memory capture completed: $memory_file"
        
        # Compress memory dump
        print_status "PROGRESS" "Compressing memory dump..."
        gzip "$memory_file"
        log_hash "$memory_file.gz" "sha256"
        print_status "SUCCESS" "Memory dump compressed: $memory_file.gz"
    else
        print_status "ERROR" "Memory capture failed"
        rm -f "$memory_file"
    fi
}

# Function to capture disk image
capture_disk_image() {
    print_status "PROGRESS" "Preparing disk image capture..."
    
    local root_device=""
    if command -v lsblk >/dev/null 2>&1; then
        root_device=$(lsblk -no PKNAME "$(df / | tail -1 | awk '{print $1}')" 2>/dev/null || echo "")
    else
        root_device=$(df / | tail -1 | awk '{print $1}' | sed 's/[0-9]*$//')
    fi
    
    if [[ -z "$root_device" ]]; then
        print_status "ERROR" "Could not determine root device"
        return
    fi
    
    print_status "INFO" "Root device: $root_device"
    
    # Notify user about long process
    print_status "WARNING" "Disk imaging will take a very long time depending on disk size"
    print_status "WARNING" "Press Ctrl+C within 2 seconds to skip disk imaging..."
    sleep 2
    
    if command -v ewfacquire >/dev/null 2>&1; then
        # Use ewfacquire for E01 format
        local image_file="$EVIDENCEPATH/$(hostname)_disk_image"
        print_status "INFO" "Using ewfacquire for E01 format: $image_file.E01"
        
        ewfacquire -t "$image_file" "$root_device" -f encase6 -D "Evidence capture at $(date)" -l "$EVIDENCEPATH/ewf.log" 2>&1 | tee "$EVIDENCEPATH/ewf_progress.log"
        
        if [[ -f "$image_file.E01" ]]; then
            log_hash "$image_file.E01" "sha256"
            print_status "SUCCESS" "Disk image created: $image_file.E01"
        else
            print_status "ERROR" "Disk imaging failed"
        fi
    else
        # Use dd as fallback
        local image_file="$EVIDENCEPATH/$(hostname)_disk_image.raw"
        print_status "INFO" "Using dd for raw format: $image_file"
        print_status "WARNING" "Raw format will be much larger than E01"
        
        # Calculate disk size for progress estimation
        local disk_size=$(blockdev --getsize64 "$root_device" 2>/dev/null || echo "0")
        if [[ "$disk_size" -gt 0 ]]; then
            local size_gb=$((disk_size / 1024 / 1024 / 1024))
            print_status "INFO" "Estimated disk size: ${size_gb}GB"
        fi
        
        dd if="$root_device" of="$image_file" bs="$REQUIRED_BS" status=progress conv=noerror,sync 2>&1 | tee "$EVIDENCEPATH/dd_progress.log"
        
        if [[ -f "$image_file" ]]; then
            log_hash "$image_file" "sha256"
            print_status "SUCCESS" "Raw disk image created: $image_file"
            
            # Compress raw image
            print_status "PROGRESS" "Compressing raw disk image (this will take a very long time)..."
            gzip "$image_file"
            log_hash "$image_file.gz" "sha256"
            print_status "SUCCESS" "Raw disk image compressed: $image_file.gz"
        else
            print_status "ERROR" "Disk imaging failed"
        fi
    fi
}

# Function to create evidence summary
create_evidence_summary() {
    print_status "PROGRESS" "Creating evidence collection summary..."
    
    local summary_file="$EVIDENCEPATH/evidence_summary.txt"
    
    {
        echo "=========================================="
        echo "        EVIDENCE COLLECTION SUMMARY"
        echo "=========================================="
        echo ""
        echo "Collection Details:"
        echo "  Start Time: $COLLECTION_START_TIME"
        echo "  End Time: $(date)"
        echo "  Hostname: $HOSTNAME"
        echo "  System Type: $SYSTEM_TYPE"
        echo "  Evidence Location: $EVIDENCEPATH"
        echo ""
        echo "Evidence Collected:"
        echo "  - System Information"
        echo "  - Process Information"
        echo "  - Network Information"
        echo "  - User History Files"
        echo "  - System Logs"
        echo "  - Recently Modified Executables"
        echo "  - Memory Dump (if AVML available)"
        echo "  - Disk Image"
        echo ""
        echo "File Integrity:"
        echo "  All evidence files have been hashed with SHA256"
        echo "  Hash log: $HASH_LOG"
        echo ""
        echo "Collection Script:"
        echo "  Script: $SCRIPT_NAME"
        echo "  Version: $SCRIPT_VERSION"
        echo "  Hash: $(sha256sum "$0" | cut -d' ' -f1)"
        echo ""
        echo "=========================================="
        echo "Collection Complete"
        echo "=========================================="
        
    } > "$summary_file"
    
    log_hash "$summary_file" "sha256"
    print_status "SUCCESS" "Evidence summary created: $summary_file"
}

# Function to display help
show_help() {
    cat << EOF
$SCRIPT_NAME - Modern Linux Evidence Collection Script

USAGE:
    sudo ./$SCRIPT_NAME <evidence_storage_path>

DESCRIPTION:
    This script performs comprehensive evidence collection from a potentially
    compromised Linux host using modern tools and techniques.

REQUIREMENTS:
    - Root privileges
    - AVML for memory capture (recommended)
    - ewfacquire for disk imaging (recommended)
    - Modern Linux tools (ss, lsof, etc.)

FEATURES:
    - System information collection
    - Process enumeration and analysis
    - Network connection capture
    - User history collection
    - Log file collection
    - Recent executable identification
    - Memory capture (AVML)
    - Disk imaging
    - Comprehensive hashing and logging

EXAMPLES:
    sudo ./$SCRIPT_NAME /media/usb/evidence
    sudo ./$SCRIPT_NAME /mnt/external_storage/incident_001

VERSION: $SCRIPT_VERSION
EOF
}

# Main function
main() {
    # Check arguments
    if [[ $# -eq 0 ]] || [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
        show_help
        exit 0
    fi
    
    EVIDENCEPATH="$1"
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        print_status "ERROR" "This script must be run with root privileges!"
        exit 1
    fi
    
    # Check if target path exists and is writable
    if [[ ! -d "$EVIDENCEPATH" ]]; then
        print_status "ERROR" "Target directory does not exist: $EVIDENCEPATH"
        exit 1
    fi
    
    if [[ ! -w "$EVIDENCEPATH" ]]; then
        print_status "ERROR" "Target directory is not writable: $EVIDENCEPATH"
        exit 1
    fi
    
    # Check if writing to physical device being analyzed
    check_physical_device "$EVIDENCEPATH"
    
    # Initialize collection
    COLLECTION_START_TIME=$(date)
    HOSTNAME=$(hostname)
    
    # Set up logging
    LOGFILE="$EVIDENCEPATH/evidence_collection.log"
    HASH_LOG="$EVIDENCEPATH/file_hashes.txt"
    
    # Create log header
    {
        echo "=========================================="
        echo "    EVIDENCE COLLECTION LOG"
        echo "=========================================="
        echo "Script: $SCRIPT_NAME"
        echo "Version: $SCRIPT_VERSION"
        echo "Start Time: $COLLECTION_START_TIME"
        echo "Hostname: $HOSTNAME"
        echo "Evidence Path: $EVIDENCEPATH"
        echo "=========================================="
        echo ""
    } > "$LOGFILE"
    
    # Create hash log header
    {
        echo "=========================================="
        echo "        FILE INTEGRITY LOG"
        echo "=========================================="
        echo "Script: $SCRIPT_NAME"
        echo "Version: $SCRIPT_VERSION"
        echo "Collection: $COLLECTION_START_TIME"
        echo "Format: TIMESTAMP - HASH_TYPE:HASH - FILE_PATH"
        echo "=========================================="
        echo ""
    } > "$HASH_LOG"
    
    print_status "INFO" "Evidence collection started"
    print_status "INFO" "Evidence will be stored in: $EVIDENCEPATH"
    print_status "INFO" "Log file: $LOGFILE"
    print_status "INFO" "Hash log: $HASH_LOG"
    
    # Detect system type
    detect_system_type
    
    # Check requirements
    check_requirements
    
    # Create evidence directory structure
    mkdir -p "$EVIDENCEPATH"
    
    # Collect evidence
    collect_system_info
    collect_process_info
    collect_network_info
    collect_user_history
    collect_log_files
    collect_recent_executables
    
    # Capture memory (if AVML available)
    capture_memory
    
    # Capture disk image
    capture_disk_image
    
    # Create summary
    create_evidence_summary
    
    # Final status
    print_status "SUCCESS" "Evidence collection completed successfully!"
    print_status "INFO" "All evidence has been collected and hashed"
    print_status "INFO" "Check the log file for detailed information: $LOGFILE"
    print_status "INFO" "Check the hash log for file integrity: $HASH_LOG"
    
    # Log final hash of log file
    log_hash "$LOGFILE" "sha256"
    log_hash "$HASH_LOG" "sha256"
    
    # Set read-only permissions on evidence
    chmod -R 444 "$EVIDENCEPATH" 2>/dev/null || true
    chmod 644 "$LOGFILE" "$HASH_LOG" 2>/dev/null || true
}

# Trap to handle script interruption
trap 'print_status "WARNING" "Script interrupted by user"; exit 130' INT TERM

# Run main function
main "$@"
