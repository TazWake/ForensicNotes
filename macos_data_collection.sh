#!/bin/bash

# =============================================================================
# Modern macOS Evidence Collection Script
# Version: 0.1
# Description: Incident response evidence collection script for macOS hosts
#              Designed to work with macOS security protections and limitations
# Requirements: Root privileges, macOS 10.15+ (Catalina and later)
# Usage: sudo ./macos_data_collection.sh /path/to/evidence
# Notes: This is an initial version of the script. It has not been tested.
#        Many areas require specialist forensic tooling not available in this script.
#
# =============================================================================

# Script Configuration
SCRIPT_VERSION="0.1"
SCRIPT_NAME="macos_data_collection.sh"
AUTHOR="Taz Wake"
CREATED_DATE="$(date '+%Y-%m-%d')"

# Colour codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Colour

# Global variables
EVIDENCE_PATH=""
LOG_FILE=""
HASH_LOG=""
SCRIPT_START_TIME=""
CURRENT_USER=""
HOSTNAME=""
MACOS_VERSION=""
SYSTEM_INTEGRITY_PROTECTION=""

# Function to display help information
show_help() {
    cat << EOF
${SCRIPT_NAME} - macOS Evidence Collection Script v${SCRIPT_VERSION}

DESCRIPTION:
    This script collects forensic evidence from macOS systems for incident response.
    It is designed to work within macOS security constraints and limitations.

USAGE:
    sudo ./${SCRIPT_NAME} <evidence_path>

PARAMETERS:
    evidence_path    Full path to directory where evidence will be stored
                     Must be writable and NOT on the system being analysed

REQUIREMENTS:
    - Root/Administrator privileges
    - macOS 10.15+ (Catalina and later)
    - Sufficient storage space for evidence collection
    - External storage device recommended

SECURITY NOTES:
    - This script respects macOS security protections
    - Some evidence may be inaccessible due to SIP, T2 chip, or FileVault
    - Memory collection requires specialist tooling not included
    - Some logs may be encrypted or protected

EXAMPLES:
    sudo ./${SCRIPT_NAME} /Volumes/ExternalDrive/evidence
    sudo ./${SCRIPT_NAME} /tmp/evidence_collection

HELP:
    ./${SCRIPT_NAME} --help    Show this help message
    ./${SCRIPT_NAME} --version Show script version

EOF
}

# Function to display version information
show_version() {
    echo "${SCRIPT_NAME} version ${SCRIPT_VERSION}"
    echo "Created: ${CREATED_DATE}"
    echo "Author: ${AUTHOR}"
    exit 0
}

# Function to print status messages with timestamps
print_status() {
    local level="$1"
    local message="$2"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")
            echo -e "${GREEN}[${timestamp}] INFO: ${message}${NC}"
            ;;
        "WARNING")
            echo -e "${YELLOW}[${timestamp}] WARNING: ${message}${NC}"
            ;;
        "ERROR")
            echo -e "${RED}[${timestamp}] ERROR: ${message}${NC}"
            ;;
        "DEBUG")
            echo -e "${BLUE}[${timestamp}] DEBUG: ${message}${NC}"
            ;;
        *)
            echo -e "[${timestamp}] ${message}"
            ;;
    esac
    
    # Log to file if available
    if [[ -n "$LOG_FILE" ]]; then
        echo "[${timestamp}] ${level}: ${message}" >> "$LOG_FILE"
    fi
}

# Function to log hash values
log_hash() {
    local file_path="$1"
    local hash_value="$2"
    local hash_type="$3"
    
    if [[ -n "$HASH_LOG" ]]; then
        echo "${hash_type},${file_path},${hash_value}" >> "$HASH_LOG"
    fi
}

# Function to check if running as root
check_root_privileges() {
    if [[ $EUID -ne 0 ]]; then
        print_status "ERROR" "This script must be run as root (use sudo)"
        print_status "ERROR" "macOS security protections require elevated privileges for evidence collection"
        exit 1
    fi
    print_status "INFO" "Root privileges confirmed"
}

# Function to check macOS version and compatibility
check_macos_compatibility() {
    # Get macOS version
    MACOS_VERSION=$(sw_vers -productVersion)
    print_status "INFO" "macOS version detected: ${MACOS_VERSION}"
    
    # Check if version is supported (10.15+)
    local major_version=$(echo "$MACOS_VERSION" | cut -d. -f1)
    local minor_version=$(echo "$MACOS_VERSION" | cut -d. -f2)
    
    if [[ $major_version -lt 10 ]] || [[ $major_version -eq 10 && $minor_version -lt 15 ]]; then
        print_status "WARNING" "macOS version ${MACOS_VERSION} may not be fully supported"
        print_status "WARNING" "Some features may not work correctly on older versions"
    fi
    
    # Check for T2 chip (affects some forensic capabilities)
    if system_profiler SPiBridgeDataType 2>/dev/null | grep -q "T2"; then
        print_status "INFO" "T2 Security Chip detected - some forensic operations may be restricted"
    fi
    
    # Check System Integrity Protection status
    if csrutil status 2>/dev/null | grep -q "enabled"; then
        SYSTEM_INTEGRITY_PROTECTION="enabled"
        print_status "INFO" "System Integrity Protection (SIP) is enabled"
        print_status "WARNING" "SIP may prevent access to some system files and directories"
    else
        SYSTEM_INTEGRITY_PROTECTION="disabled"
        print_status "WARNING" "System Integrity Protection (SIP) is disabled"
        print_status "WARNING" "This is unusual and may indicate system compromise or manual disablement"
    fi
}

# Function to validate evidence path
validate_evidence_path() {
    local path="$1"
    
    if [[ -z "$path" ]]; then
        print_status "ERROR" "Evidence path must be specified"
        show_help
        exit 1
    fi
    
    # Check if path is absolute
    if [[ ! "$path" = /* ]]; then
        print_status "ERROR" "Evidence path must be an absolute path"
        exit 1
    fi
    
    # Check if path is on the system being analysed
    local system_root=$(df / | awk 'NR==2 {print $1}')
    local evidence_device=$(df "$path" 2>/dev/null | awk 'NR==2 {print $1}')
    
    if [[ "$system_root" == "$evidence_device" ]]; then
        print_status "ERROR" "Evidence path is on the system being analysed"
        print_status "ERROR" "This could overwrite evidence and is not recommended"
        print_status "ERROR" "Please use an external storage device"
        exit 1
    fi
    
    # Create directory if it doesn't exist
    if [[ ! -d "$path" ]]; then
        mkdir -p "$path"
        if [[ $? -ne 0 ]]; then
            print_status "ERROR" "Failed to create evidence directory: $path"
            exit 1
        fi
    fi
    
    # Check if directory is writable
    if [[ ! -w "$path" ]]; then
        print_status "ERROR" "Evidence directory is not writable: $path"
        exit 1
    fi
    
    EVIDENCE_PATH="$path"
    print_status "INFO" "Evidence path validated: $EVIDENCE_PATH"
}

# Function to initialise logging
initialise_logging() {
    SCRIPT_START_TIME=$(date '+%Y-%m-%d %H:%M:%S')
    CURRENT_USER=$(whoami)
    HOSTNAME=$(hostname)
    
    # Create log files
    LOG_FILE="$EVIDENCE_PATH/evidence_collection.log"
    HASH_LOG="$EVIDENCE_PATH/evidence_hashes.csv"
    
    # Create hash log header
    echo "hash_type,file_path,hash_value" > "$HASH_LOG"
    
    # Log script start
    print_status "INFO" "=== macOS Evidence Collection Script Started ==="
    print_status "INFO" "Script Version: ${SCRIPT_VERSION}"
    print_status "INFO" "Start Time: ${SCRIPT_START_TIME}"
    print_status "INFO" "User: ${CURRENT_USER}"
    print_status "INFO" "Hostname: ${HOSTNAME}"
    print_status "INFO" "macOS Version: ${MACOS_VERSION}"
    print_status "INFO" "SIP Status: ${SYSTEM_INTEGRITY_PROTECTION}"
    print_status "INFO" "Evidence Path: ${EVIDENCE_PATH}"
    print_status "INFO" "Log File: ${LOG_FILE}"
    print_status "INFO" "Hash Log: ${HASH_LOG}"
}

# Function to collect system information
collect_system_information() {
    print_status "INFO" "Collecting system information..."
    
    local sysinfo_dir="$EVIDENCE_PATH/system_information"
    mkdir -p "$sysinfo_dir"
    
    # Basic system information
    print_status "INFO" "  - System overview"
    system_profiler SPHardwareDataType > "$sysinfo_dir/hardware_info.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    Hardware information collected"
        log_hash "$sysinfo_dir/hardware_info.txt" "$(md5 "$sysinfo_dir/hardware_info.txt" | awk '{print $4}')" "MD5"
    else
        print_status "WARNING" "    Failed to collect hardware information"
    fi
    
    # macOS version details
    print_status "INFO" "  - macOS version details"
    sw_vers > "$sysinfo_dir/macos_version.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    macOS version information collected"
        log_hash "$sysinfo_dir/macos_version.txt" "$(md5 "$sysinfo_dir/macos_version.txt" | awk '{print $4}')" "MD5"
    fi
    
    # Kernel information
    print_status "INFO" "  - Kernel information"
    uname -a > "$sysinfo_dir/kernel_info.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    Kernel information collected"
        log_hash "$sysinfo_dir/kernel_info.txt" "$(md5 "$sysinfo_dir/kernel_info.txt" | awk '{print $4}')" "MD5"
    fi
    
    # System uptime
    print_status "INFO" "  - System uptime"
    uptime > "$sysinfo_dir/uptime.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    Uptime information collected"
        log_hash "$sysinfo_dir/uptime.txt" "$(md5 "$sysinfo_dir/uptime.txt" | awk '{print $4}')" "MD5"
    fi
    
    # Mounted filesystems
    print_status "INFO" "  - Mounted filesystems"
    mount > "$sysinfo_dir/mounted_filesystems.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    Mounted filesystems information collected"
        log_hash "$sysinfo_dir/mounted_filesystems.txt" "$(md5 "$sysinfo_dir/mounted_filesystems.txt" | awk '{print $4}')" "MD5"
    fi
    
    # Disk usage
    print_status "INFO" "  - Disk usage"
    df -h > "$sysinfo_dir/disk_usage.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    Disk usage information collected"
        log_hash "$sysinfo_dir/disk_usage.txt" "$(md5 "$sysinfo_dir/disk_usage.txt" | awk '{print $4}')" "MD5"
    fi
    
    # Network interfaces
    print_status "INFO" "  - Network interfaces"
    ifconfig > "$sysinfo_dir/network_interfaces.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    Network interfaces information collected"
        log_hash "$sysinfo_dir/network_interfaces.txt" "$(md5 "$sysinfo_dir/network_interfaces.txt" | awk '{print $4}')" "MD5"
    fi
    
    print_status "INFO" "System information collection completed"
}

# Function to collect process information
collect_process_information() {
    print_status "INFO" "Collecting process information..."
    
    local process_dir="$EVIDENCE_PATH/process_information"
    mkdir -p "$process_dir"
    
    # Current running processes
    print_status "INFO" "  - Running processes (ps aux)"
    ps aux > "$process_dir/running_processes.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    Process list collected"
        log_hash "$process_dir/running_processes.txt" "$(md5 "$process_dir/running_processes.txt" | awk '{print $4}')" "MD5"
    else
        print_status "WARNING" "    Failed to collect process list"
    fi
    
    # Process tree
    print_status "INFO" "  - Process tree"
    ps -ef > "$process_dir/process_tree.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    Process tree collected"
        log_hash "$process_dir/process_tree.txt" "$(md5 "$process_dir/process_tree.txt" | awk '{print $4}')" "MD5"
    fi
    
    # Loaded kernel extensions
    print_status "INFO" "  - Loaded kernel extensions"
    kextstat > "$process_dir/loaded_kernel_extensions.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    Kernel extensions information collected"
        log_hash "$process_dir/loaded_kernel_extensions.txt" "$(md5 "$process_dir/loaded_kernel_extensions.txt" | awk '{print $4}')" "MD5"
    else
        print_status "WARNING" "    Failed to collect kernel extensions information"
    fi
    
    # Launch daemons and agents
    print_status "INFO" "  - Launch daemons and agents"
    launchctl list > "$process_dir/launch_services.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    Launch services information collected"
        log_hash "$process_dir/launch_services.txt" "$(md5 "$process_dir/launch_services.txt" | awk '{print $4}')" "MD5"
    else
        print_status "WARNING" "    Failed to collect launch services information"
    fi
    
    # System launch daemons directory
    print_status "INFO" "  - System launch daemons"
    ls -la /System/Library/LaunchDaemons/ > "$process_dir/system_launch_daemons.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    System launch daemons listed"
        log_hash "$process_dir/system_launch_daemons.txt" "$(md5 "$process_dir/system_launch_daemons.txt" | awk '{print $4}')" "MD5"
    fi
    
    # User launch agents (if accessible)
    print_status "INFO" "  - User launch agents"
    for user_home in /Users/*; do
        if [[ -d "$user_home" ]]; then
            local username=$(basename "$user_home")
            local user_agents_dir="$process_dir/user_launch_agents_${username}"
            mkdir -p "$user_agents_dir"
            
            if [[ -d "$user_home/Library/LaunchAgents" ]]; then
                ls -la "$user_home/Library/LaunchAgents/" > "$user_agents_dir/launch_agents.txt" 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    print_status "INFO" "    Launch agents for user $username collected"
                    log_hash "$user_agents_dir/launch_agents.txt" "$(md5 "$user_agents_dir/launch_agents.txt" | awk '{print $4}')" "MD5"
                fi
            fi
        fi
    done
    
    print_status "INFO" "Process information collection completed"
}

# Function to collect network information
collect_network_information() {
    print_status "INFO" "Collecting network information..."
    
    local network_dir="$EVIDENCE_PATH/network_information"
    mkdir -p "$network_dir"
    
    # Active network connections
    print_status "INFO" "  - Active network connections"
    netstat -an > "$network_dir/active_connections.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    Active connections collected"
        log_hash "$network_dir/active_connections.txt" "$(md5 "$network_dir/active_connections.txt" | awk '{print $4}')" "MD5"
    else
        print_status "WARNING" "    Failed to collect active connections"
    fi
    
    # Network routing table
    print_status "INFO" "  - Network routing table"
    netstat -rn > "$network_dir/routing_table.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    Routing table collected"
        log_hash "$network_dir/routing_table.txt" "$(md5 "$network_dir/routing_table.txt" | awk '{print $4}')" "MD5"
    fi
    
    # ARP table
    print_status "INFO" "  - ARP table"
    arp -a > "$network_dir/arp_table.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    ARP table collected"
        log_hash "$network_dir/arp_table.txt" "$(md5 "$network_dir/arp_table.txt" | awk '{print $4}')" "MD5"
    fi
    
    # DNS configuration
    print_status "INFO" "  - DNS configuration"
    cat /etc/resolv.conf > "$network_dir/dns_config.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    DNS configuration collected"
        log_hash "$network_dir/dns_config.txt" "$(md5 "$network_dir/dns_config.txt" | awk '{print $4}')" "MD5"
    fi
    
    # Network interfaces with IP addresses
    print_status "INFO" "  - Network interface details"
    ifconfig -a > "$network_dir/interface_details.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    Interface details collected"
        log_hash "$network_dir/interface_details.txt" "$(md5 "$network_dir/interface_details.txt" | awk '{print $4}')" "MD5"
    fi
    
    # Firewall rules (if accessible)
    print_status "INFO" "  - Firewall rules"
    pfctl -s rules > "$network_dir/firewall_rules.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "    Firewall rules collected"
        log_hash "$network_dir/firewall_rules.txt" "$(md5 "$network_dir/firewall_rules.txt" | awk '{print $4}')" "MD5"
    else
        print_status "WARNING" "    Firewall rules not accessible (may require specialist tooling)"
    fi
    
    print_status "INFO" "Network information collection completed"
}

# Function to collect user artifacts
collect_user_artifacts() {
    print_status "INFO" "Collecting user artifacts..."
    
    local user_dir="$EVIDENCE_PATH/user_artifacts"
    mkdir -p "$user_dir"
    
    # Iterate through user directories
    for user_home in /Users/*; do
        if [[ -d "$user_home" ]]; then
            local username=$(basename "$user_home")
            print_status "INFO" "  - Collecting artifacts for user: $username"
            
            local user_artifacts_dir="$user_dir/$username"
            mkdir -p "$user_artifacts_dir"
            
            # Shell history files
            print_status "INFO" "    - Shell history files"
            
            # zsh history (default shell in modern macOS)
            if [[ -f "$user_home/.zsh_history" ]]; then
                cp "$user_home/.zsh_history" "$user_artifacts_dir/zsh_history.txt" 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    print_status "INFO" "      zsh history collected"
                    log_hash "$user_artifacts_dir/zsh_history.txt" "$(md5 "$user_artifacts_dir/zsh_history.txt" | awk '{print $4}')" "MD5"
                fi
            fi
            
            # bash history (if present)
            if [[ -f "$user_home/.bash_history" ]]; then
                cp "$user_home/.bash_history" "$user_artifacts_dir/bash_history.txt" 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    print_status "INFO" "      bash history collected"
                    log_hash "$user_artifacts_dir/bash_history.txt" "$(md5 "$user_artifacts_dir/bash_history.txt" | awk '{print $4}')" "MD5"
                fi
            fi
            
            # fish history (if present)
            if [[ -f "$user_home/.local/share/fish/fish_history" ]]; then
                cp "$user_home/.local/share/fish/fish_history" "$user_artifacts_dir/fish_history.txt" 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    print_status "INFO" "      fish history collected"
                    log_hash "$user_artifacts_dir/fish_history.txt" "$(md5 "$user_artifacts_dir/fish_history.txt" | awk '{print $4}')" "MD5"
                fi
            fi
            
            # SSH configuration
            print_status "INFO" "    - SSH configuration"
            if [[ -d "$user_home/.ssh" ]]; then
                cp -r "$user_home/.ssh" "$user_artifacts_dir/ssh_config" 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    print_status "INFO" "      SSH configuration collected"
                    # Hash the directory contents
                    find "$user_artifacts_dir/ssh_config" -type f -exec md5 {} \; > "$user_artifacts_dir/ssh_config_hashes.txt" 2>/dev/null
                    if [[ $? -eq 0 ]]; then
                        log_hash "$user_artifacts_dir/ssh_config_hashes.txt" "$(md5 "$user_artifacts_dir/ssh_config_hashes.txt" | awk '{print $4}')" "MD5"
                    fi
                fi
            fi
            
            # Recent files
            print_status "INFO" "    - Recent files"
            if [[ -d "$user_home/Library/Application Support/com.apple.sharedfilelist" ]]; then
                # This is complex and may require specialist tooling
                print_status "WARNING" "      Recent files require specialist tooling for proper extraction"
                print_status "WARNING" "      Placeholder: Use tools like plistutil, sqlite3, or specialist forensic tools"
            fi
            
            # Desktop and Downloads directories (file listings)
            print_status "INFO" "    - Desktop and Downloads contents"
            if [[ -d "$user_home/Desktop" ]]; then
                ls -la "$user_home/Desktop" > "$user_artifacts_dir/desktop_contents.txt" 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    print_status "INFO" "      Desktop contents listed"
                    log_hash "$user_artifacts_dir/desktop_contents.txt" "$(md5 "$user_artifacts_dir/desktop_contents.txt" | awk '{print $4}')" "MD5"
                fi
            fi
            
            if [[ -d "$user_home/Downloads" ]]; then
                ls -la "$user_home/Downloads" > "$user_artifacts_dir/downloads_contents.txt" 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    print_status "INFO" "      Downloads contents listed"
                    log_hash "$user_artifacts_dir/downloads_contents.txt" "$(md5 "$user_artifacts_dir/downloads_contents.txt" | awk '{print $4}')" "MD5"
                fi
            fi
            
            # Browser data (if accessible)
            print_status "INFO" "    - Browser data (if accessible)"
            print_status "WARNING" "      Browser data extraction requires specialist tooling"
            print_status "WARNING" "      Consider: Browser History Viewer, specialist forensic tools"
            
            # Keychain access (if possible)
            print_status "INFO" "    - Keychain information"
            print_status "WARNING" "      Keychain access requires specialist tooling and may be restricted"
            print_status "WARNING" "      Consider: keychain_dump, specialist forensic tools"
        fi
    done
    
    print_status "INFO" "User artifacts collection completed"
}

# Function to collect system logs
collect_system_logs() {
    print_status "INFO" "Collecting system logs..."
    
    local logs_dir="$EVIDENCE_PATH/system_logs"
    mkdir -p "$logs_dir"
    
    # Traditional log files (if accessible)
    print_status "INFO" "  - Traditional log files"
    
    # System log
    if [[ -f "/var/log/system.log" ]]; then
        cp "/var/log/system.log" "$logs_dir/system.log" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            print_status "INFO" "    System log collected"
            log_hash "$logs_dir/system.log" "$(md5 "$logs_dir/system.log" | awk '{print $4}')" "MD5"
        fi
    else
        print_status "WARNING" "    System log not accessible (may be in Unified Logs)"
    fi
    
    # Secure log (if present)
    if [[ -f "/var/log/secure.log" ]]; then
        cp "/var/log/secure.log" "$logs_dir/secure.log" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            print_status "INFO" "    Secure log collected"
            log_hash "$logs_dir/secure.log" "$(md5 "$logs_dir/secure.log" | awk '{print $4}')" "MD5"
        fi
    fi
    
    # Unified Logs (macOS 10.12+)
    print_status "INFO" "  - Unified Logs (macOS 10.12+)"
    print_status "WARNING" "    Unified Logs extraction is complex and requires specialist tooling"
    print_status "WARNING" "    Consider: log command line tools, specialist forensic tools"
    
    # Attempt to collect some Unified Logs (basic approach)
    print_status "INFO" "    - Attempting basic Unified Logs collection"
    
    # System logs from last 24 hours
    log show --predicate 'eventType == logEvent' --info --last 24h > "$logs_dir/unified_logs_24h.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "      Unified Logs (24h) collected"
        log_hash "$logs_dir/unified_logs_24h.txt" "$(md5 "$logs_dir/unified_logs_24h.txt" | awk '{print $4}')" "MD5"
    else
        print_status "WARNING" "      Failed to collect Unified Logs (may require specialist tooling)"
    fi
    
    # Security logs from last 24 hours
    log show --predicate 'category == "security"' --info --last 24h > "$logs_dir/security_logs_24h.txt" 2>/dev/null
    if [[ $? -eq 0 ]]; then
        print_status "INFO" "      Security logs (24h) collected"
        log_hash "$logs_dir/security_logs_24h.txt" "$(md5 "$logs_dir/security_logs_24h.txt" | awk '{print $4}')" "MD5"
    else
        print_status "WARNING" "      Failed to collect security logs"
    fi
    
    # Audit logs (if present)
    print_status "INFO" "  - Audit logs"
    if [[ -d "/var/audit" ]]; then
        ls -la /var/audit/ > "$logs_dir/audit_directory_listing.txt" 2>/dev/null
        if [[ $? -eq 0 ]]; then
            print_status "INFO" "    Audit directory listing collected"
            log_hash "$logs_dir/audit_directory_listing.txt" "$(md5 "$logs_dir/audit_directory_listing.txt" | awk '{print $4}')" "MD5"
        fi
        
        # Note: Full audit log extraction requires specialist tooling
        print_status "WARNING" "    Full audit log extraction requires specialist tooling"
        print_status "WARNING" "    Consider: praudit, specialist forensic tools"
    fi
    
    print_status "INFO" "System logs collection completed"
}

# Function to identify recently modified executables
identify_recent_executables() {
    print_status "INFO" "Identifying recently modified executables..."
    
    local executables_dir="$EVIDENCE_PATH/recent_executables"
    mkdir -p "$executables_dir"
    
    # Find executables modified in the last 5 days
    print_status "INFO" "  - Searching for executables modified in last 5 days"
    
    # Search in common executable locations
    local search_paths=("/usr/bin" "/usr/sbin" "/usr/local/bin" "/usr/local/sbin" "/opt" "/Applications" "/System/Applications")
    
    for search_path in "${search_paths[@]}"; do
        if [[ -d "$search_path" ]]; then
            print_status "INFO" "    - Searching in: $search_path"
            
            # Find executables modified in last 5 days
            find "$search_path" -type f -executable -mtime -5 -exec ls -la {} \; > "$executables_dir/recent_executables_$(basename "$search_path").txt" 2>/dev/null
            
            if [[ $? -eq 0 ]]; then
                local file_count=$(wc -l < "$executables_dir/recent_executables_$(basename "$search_path").txt")
                print_status "INFO" "      Found $file_count recently modified executables"
                
                # Generate MD5 hashes for found executables
                find "$search_path" -type f -executable -mtime -5 -exec md5 {} \; > "$executables_dir/recent_executables_$(basename "$search_path")_hashes.txt" 2>/dev/null
                if [[ $? -eq 0 ]]; then
                    print_status "INFO" "      MD5 hashes generated"
                    log_hash "$executables_dir/recent_executables_$(basename "$search_path")_hashes.txt" "$(md5 "$executables_dir/recent_executables_$(basename "$search_path")_hashes.txt" | awk '{print $4}')" "MD5"
                fi
                
                log_hash "$executables_dir/recent_executables_$(basename "$search_path").txt" "$(md5 "$executables_dir/recent_executables_$(basename "$search_path").txt" | awk '{print $4}')" "MD5"
            else
                print_status "WARNING" "      Failed to search in $search_path"
            fi
        fi
    done
    
    # Search in user directories for recently modified executables
    print_status "INFO" "  - Searching user directories for recently modified executables"
    for user_home in /Users/*; do
        if [[ -d "$user_home" ]]; then
            local username=$(basename "$user_home")
            find "$user_home" -type f -executable -mtime -5 -exec ls -la {} \; > "$executables_dir/recent_executables_user_${username}.txt" 2>/dev/null
            
            if [[ $? -eq 0 ]]; then
                local file_count=$(wc -l < "$executables_dir/recent_executables_user_${username}.txt")
                if [[ $file_count -gt 0 ]]; then
                    print_status "INFO" "      Found $file_count recently modified executables for user $username"
                    
                    # Generate MD5 hashes
                    find "$user_home" -type f -executable -mtime -5 -exec md5 {} \; > "$executables_dir/recent_executables_user_${username}_hashes.txt" 2>/dev/null
                    if [[ $? -eq 0 ]]; then
                        print_status "INFO" "      MD5 hashes generated for user $username"
                        log_hash "$executables_dir/recent_executables_user_${username}_hashes.txt" "$(md5 "$executables_dir/recent_executables_user_${username}_hashes.txt" | awk '{print $4}')" "MD5"
                    fi
                    
                    log_hash "$executables_dir/recent_executables_user_${username}.txt" "$(md5 "$executables_dir/recent_executables_user_${username}.txt" | awk '{print $4}')" "MD5"
                fi
            fi
        fi
    done
    
    print_status "INFO" "Recent executables identification completed"
}

# Function to attempt memory collection (placeholder)
attempt_memory_collection() {
    print_status "INFO" "Memory collection section..."
    
    local memory_dir="$EVIDENCE_PATH/memory_collection"
    mkdir -p "$memory_dir"
    
    print_status "WARNING" "  Memory collection on macOS requires specialist tooling"
    print_status "WARNING" "  This script cannot perform memory collection"
    print_status "WARNING" "  Consider the following tools:"
    print_status "WARNING" "    - Mac Memory Reader (requires specialist access)"
    print_status "WARNING" "    - OSXPMem (if available and compatible)"
    print_status "WARNING" "    - Specialist forensic tools with macOS support"
    
    # Create a placeholder file explaining the limitations
    cat > "$memory_dir/memory_collection_limitations.txt" << 'EOF'
MEMORY COLLECTION LIMITATIONS ON macOS

This script cannot perform memory collection due to macOS security protections:

1. System Integrity Protection (SIP) - Prevents access to kernel memory
2. T2 Security Chip - Additional hardware-level protections
3. Kernel extensions - Restricted loading of forensic tools
4. Secure Boot - Prevents unauthorised kernel modifications

RECOMMENDED APPROACHES:
- Use specialist forensic tools designed for macOS
- Consider hardware-based memory acquisition
- Work with Apple's security team if required
- Document all attempts and limitations

TOOLS TO CONSIDER:
- Mac Memory Reader (requires specialist access)
- OSXPMem (if available and compatible)
- Specialist forensic tools with macOS support
- Hardware-based acquisition methods

NOTE: This is a significant limitation for macOS forensics and requires
specialist knowledge and tools beyond the scope of this script.
EOF
    
    log_hash "$memory_dir/memory_collection_limitations.txt" "$(md5 "$memory_dir/memory_collection_limitations.txt" | awk '{print $4}')" "MD5"
    
    print_status "INFO" "Memory collection limitations documented"
}

# Function to attempt disk imaging (placeholder)
attempt_disk_imaging() {
    print_status "INFO" "Disk imaging section..."
    
    local disk_dir="$EVIDENCE_PATH/disk_imaging"
    mkdir -p "$disk_dir"
    
    print_status "WARNING" "  Disk imaging on macOS requires specialist tooling"
    print_status "WARNING" "  This script cannot perform full disk imaging"
    print_status "WARNING" "  Consider the following tools:"
    print_status "WARNING" "    - FTK Imager (if available)"
    print_status "WARNING" "    - dd (if accessible and compatible)"
    print_status "WARNING" "    - Specialist forensic tools with macOS support"
    
    # Create a placeholder file explaining the limitations
    cat > "$disk_dir/disk_imaging_limitations.txt" << 'EOF'
DISK IMAGING LIMITATIONS ON macOS

This script cannot perform full disk imaging due to macOS security protections:

1. System Integrity Protection (SIP) - Prevents access to system volumes
2. FileVault encryption - May encrypt entire disk
3. APFS restrictions - Advanced filesystem protections
4. Secure Boot - Prevents unauthorised disk access

RECOMMENDED APPROACHES:
- Use specialist forensic tools designed for macOS
- Consider hardware-based disk acquisition
- Work with Apple's security team if required
- Document all attempts and limitations

TOOLS TO CONSIDER:
- FTK Imager (if available and compatible)
- dd (if accessible and compatible)
- Specialist forensic tools with macOS support
- Hardware-based acquisition methods

LIMITED CAPABILITIES:
- File listing and metadata collection
- Specific file extraction (if accessible)
- Hash generation for accessible files
- Directory structure documentation

NOTE: This is a significant limitation for macOS forensics and requires
specialist knowledge and tools beyond the scope of this script.
EOF
    
    log_hash "$disk_dir/disk_imaging_limitations.txt" "$(md5 "$disk_dir/disk_imaging_limitations.txt" | awk '{print $4}')" "MD5"
    
    print_status "INFO" "Disk imaging limitations documented"
}

# Function to create evidence summary
create_evidence_summary() {
    print_status "INFO" "Creating evidence summary..."
    
    local summary_file="$EVIDENCE_PATH/evidence_summary.txt"
    
    cat > "$summary_file" << EOF
=============================================================================
                    macOS EVIDENCE COLLECTION SUMMARY
=============================================================================

Collection Details:
    Script Version: ${SCRIPT_VERSION}
    Collection Date: $(date '+%Y-%m-%d %H:%M:%S')
    Start Time: ${SCRIPT_START_TIME}
    End Time: $(date '+%Y-%m-%d %H:%M:%S')
    User: ${CURRENT_USER}
    Hostname: ${HOSTNAME}
    macOS Version: ${MACOS_VERSION}
    SIP Status: ${SYSTEM_INTEGRITY_PROTECTION}
    Evidence Path: ${EVIDENCE_PATH}

Evidence Collected:
    - System Information: Hardware, version, kernel, uptime, filesystems
    - Process Information: Running processes, kernel extensions, launch services
    - Network Information: Connections, routing, ARP, DNS, firewall
    - User Artifacts: Shell history, SSH configs, user directories
    - System Logs: Traditional logs, Unified Logs (basic), audit logs
    - Recent Executables: Files modified in last 5 days with MD5 hashes
    - Memory Collection: Limitations documented (requires specialist tools)
    - Disk Imaging: Limitations documented (requires specialist tools)

Files Collected:
$(find "$EVIDENCE_PATH" -type f -name "*.txt" -o -name "*.log" -o -name "*.csv" | sort | sed 's/^/    - /')

Hash Log: ${HASH_LOG}
Log File: ${LOG_FILE}

IMPORTANT NOTES:
    - This is a basic evidence collection script
    - Many areas require specialist forensic tooling
    - Memory and disk imaging are not possible with this script
    - Some logs may be encrypted or protected
    - Consider using specialist tools for comprehensive forensics

RECOMMENDATIONS:
    - Review all collected evidence thoroughly
    - Use specialist tools for memory and disk analysis
    - Consider hardware-based acquisition methods
    - Document all limitations and workarounds
    - Work with Apple's security team if required

=============================================================================
EOF
    
    log_hash "$summary_file" "$(md5 "$summary_file" | awk '{print $4}')" "MD5"
    print_status "INFO" "Evidence summary created: $summary_file"
}

# Function to handle script cleanup
cleanup() {
    print_status "INFO" "Script cleanup completed"
    print_status "INFO" "=== macOS Evidence Collection Script Finished ==="
    print_status "INFO" "End Time: $(date '+%Y-%m-%d %H:%M:%S')"
    print_status "INFO" "Evidence stored in: $EVIDENCE_PATH"
    print_status "INFO" "Log file: $LOG_FILE"
    print_status "INFO" "Hash log: $HASH_LOG"
}

# Main function
main() {
    # Parse command line arguments
    case "${1:-}" in
        --help|-h)
            show_help
            exit 0
            ;;
        --version|-v)
            show_version
            exit 0
            ;;
        "")
            print_status "ERROR" "Evidence path must be specified"
            show_help
            exit 1
            ;;
        *)
            # Assume it's the evidence path
            ;;
    esac
    
    # Initial checks
    check_root_privileges
    check_macos_compatibility
    validate_evidence_path "$1"
    initialise_logging
    
    # Evidence collection
    collect_system_information
    collect_process_information
    collect_network_information
    collect_user_artifacts
    collect_system_logs
    identify_recent_executables
    
    # Placeholder sections (require specialist tooling)
    attempt_memory_collection
    attempt_disk_imaging
    
    # Final steps
    create_evidence_summary
    cleanup
    
    print_status "INFO" "Evidence collection completed successfully"
    print_status "INFO" "All evidence has been hashed and logged"
    print_status "WARNING" "Remember: This script has limitations and may require specialist tools"
}

# Trap to ensure cleanup runs on exit
trap cleanup EXIT

# Run main function with all arguments
main "$@"
