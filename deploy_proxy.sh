#!/bin/bash

# Script to deploy the SOCKS5 proxy to remote servers.

LOG_FILE="deployment.log"
PROXY_BINARY_PATH="./socks5proxy" # Assuming the binary is in the same directory

# --- Configurable Variables ---
SSH_USER="" # Set to your SSH username if needed, e.g., "user"
REMOTE_PROXY_EXEC_PATH="/tmp/socks5proxy_deploy_instance" # Path on remote server for the proxy binary
PROXY_SOCKS_USER="" # Username for the SOCKS5 proxy itself (leave empty for no auth)
PROXY_SOCKS_PASS="" # Password for the SOCKS5 proxy itself (leave empty for no auth)

# Define default ports to try for the proxy
PROXY_PORTS=(1080 1081 8080 8888)

# --- Logging Function ---
log_message() {
    local type="$1"
    local message="$2"
    echo "$(date '+%Y-%m-%d %H:%M:%S') - $type - $message" | tee -a "$LOG_FILE"
}

# --- Usage Instructions ---
usage() {
    echo "Usage: $0 <server_ip1> [server_ip2] ..."
    echo "  Deploys the SOCKS5 proxy to the specified server IPs."
    echo "  Configure SSH_USER, PROXY_SOCKS_USER, PROXY_SOCKS_PASS at the top of the script if needed."
    echo "Example: $0 192.168.1.100 192.168.1.101"
    exit 1
}

# --- Remote Operation Functions ---

# Check if proxy is running on a specific port on the remote server
# Returns 0 if running, 1 otherwise
check_proxy_status_on_port_remote() {
    local server_ip_full="$1"
    local port="$2"
    local remote_exec_path="$3"

    log_message "INFO" "Checking proxy status on $server_ip_full for port $port (exec: $remote_exec_path)..."

    # Command to find the proxy process. Note: pgrep pattern might need tuning.
    # We check for the executable path and the specific port it's listening on.
    # The pattern "0.0.0.0 $port" assumes the proxy binds to 0.0.0.0.
    # If it binds to a specific IP, this pattern would need to be more general or specific.
    local check_command="pgrep -f \"$remote_exec_path .* $port\""

    if ssh "$server_ip_full" "$check_command" > /dev/null 2>&1; then
        log_message "INFO" "Proxy process found running on $server_ip_full:$port."
        return 0 # Proxy is running
    else
        log_message "INFO" "No proxy process found running on $server_ip_full:$port."
        return 1 # Proxy is not running or error
    fi
}

# Find an available port on the remote server from a list of ports
# Echos the first available port and returns 0, or returns 1 if no port is free.
find_available_port_remote() {
    local server_ip_full="$1"
    shift
    local ports_to_check_str="$1" # Expecting a space-separated string of ports

    log_message "INFO" "Finding available port on $server_ip_full among ($ports_to_check_str)..."

    for port in $ports_to_check_str; do
        log_message "DEBUG" "Checking port $port on $server_ip_full..."
        # 'ss -tlpn' lists TCP listening sockets. grep -q exits immediately if found.
        # If grep finds the port, it means it's in use (exit code 0). We want a non-zero exit code.
        if ! ssh "$server_ip_full" "ss -tlpn | grep -q ':$port '" > /dev/null 2>&1; then
            log_message "INFO" "Port $port appears to be available on $server_ip_full."
            echo "$port"
            return 0 # Port found
        else
            log_message "DEBUG" "Port $port is currently in use on $server_ip_full."
        fi
    done

    log_message "WARN" "No available port found on $server_ip_full from the list ($ports_to_check_str)."
    echo "" # Echo nothing if no port found
    return 1 # No port found
}

# Deploy the proxy to the remote server
# Returns 0 on success, 1 on failure
deploy_proxy_remote() {
    local server_ip_full="$1"
    local port="$2"
    local local_binary_path="$3"
    local remote_exec_path="$4"
    local socks_user="$5"
    local socks_pass="$6"

    log_message "INFO" "Attempting to deploy proxy to $server_ip_full on port $port..."

    # 1. SCP the proxy binary
    log_message "INFO" "Copying proxy binary from '$local_binary_path' to '$server_ip_full:$remote_exec_path'..."
    if ! scp -q "$local_binary_path" "$server_ip_full:$remote_exec_path"; then
        log_message "ERROR" "SCP failed to copy '$local_binary_path' to '$server_ip_full:$remote_exec_path'."
        return 1
    fi
    log_message "INFO" "Proxy binary copied successfully."

    # 2. SSH to the server and start the proxy
    # Ensure remote path is executable
    ssh "$server_ip_full" "chmod +x $remote_exec_path"

    local remote_log_file="/tmp/socks5proxy_${port}.log"
    # The command ensures CGO_ENABLED=0 for static linking behavior if binary was dynamic for some reason. - This comment is no longer accurate as CGO_ENABLED=0 is for build time.
    #nohup command > log 2>&1 &
    local remote_command="nohup \"$remote_exec_path\" \"0.0.0.0\" \"$port\" \"$socks_user\" \"$socks_pass\" > \"$remote_log_file\" 2>&1 &"

    log_message "INFO" "Executing remote command on $server_ip_full: $remote_command"
    if ssh "$server_ip_full" "$remote_command"; then
        log_message "SUCCESS" "Proxy deployment command executed on $server_ip_full:$port. Check remote log: $remote_log_file"
        # Give it a moment to start up before a potential quick check
        sleep 2
        if check_proxy_status_on_port_remote "$server_ip_full" "$port" "$remote_exec_path"; then
             log_message "INFO" "Proxy confirmed running after deployment on $server_ip_full:$port."
             return 0
        else
             log_message "WARN" "Proxy deployment command sent, but status check failed or process not found immediately on $server_ip_full:$port. Check remote logs: $remote_log_file."
             return 1 # Or consider it a success if nohup command itself succeeded. For now, be stricter.
        fi
    else
        log_message "ERROR" "SSH command execution failed for deploying proxy on $server_ip_full:$port."
        return 1
    fi
}

# --- Main Script ---

# Parse command-line arguments
if [ "$#" -lt 1 ]; then
    usage
fi
SERVER_IPS=("$@")

log_message "INFO" "Starting SOCKS5 proxy deployment script for servers: ${SERVER_IPS[*]}"
log_message "INFO" "SSH User: ${SSH_USER:-'(none specified, using default)'}"
log_message "INFO" "SOCKS5 Proxy Auth: User='${PROXY_SOCKS_USER:-'(none)'}', Pass='${PROXY_SOCKS_PASS:+'***** (set)'}'"


if [ ! -f "$PROXY_BINARY_PATH" ]; then
    log_message "ERROR" "Proxy binary not found at $PROXY_BINARY_PATH. Please build it first (e.g., using 'go build -o $PROXY_BINARY_PATH main.go')."
    exit 1
fi
log_message "INFO" "Using local proxy binary from: $PROXY_BINARY_PATH"


for server_ip_raw in "${SERVER_IPS[@]}"; do
    log_message "INFO" "--------------------------------------------------"
    log_message "INFO" "Processing server: $server_ip_raw"
    log_message "INFO" "--------------------------------------------------"

    server_ip_target="$server_ip_raw"
    if [ -n "$SSH_USER" ]; then
        server_ip_target="$SSH_USER@$server_ip_raw"
    fi
    log_message "INFO" "Effective remote target: $server_ip_target"

    # 1. Check if proxy is already running on any of the PROXY_PORTS
    is_already_running=false
    running_port=""
    for port_to_check in "${PROXY_PORTS[@]}"; do
        if check_proxy_status_on_port_remote "$server_ip_target" "$port_to_check" "$REMOTE_PROXY_EXEC_PATH"; then
            is_already_running=true
            running_port=$port_to_check
            break
        fi
    done

    if $is_already_running; then
        log_message "INFO" "Proxy is already running on $server_ip_target:$running_port. Skipping deployment."
    else
        log_message "INFO" "No existing proxy found running on standard ports on $server_ip_target. Attempting deployment."

        # 2. Find an available port from the PROXY_PORTS list (passed as a string)
        ports_string="${PROXY_PORTS[*]}" # Convert array to space-separated string
        selected_port=$(find_available_port_remote "$server_ip_target" "$ports_string")

        if [ $? -ne 0 ] || [ -z "$selected_port" ]; then
            log_message "ERROR" "Could not find an available port on $server_ip_target from the list: (${PROXY_PORTS[*]}). Skipping deployment for this server."
            continue
        fi
        log_message "INFO" "Selected port $selected_port for deployment on $server_ip_target."

        # 3. Deploy the proxy
        if deploy_proxy_remote "$server_ip_target" "$selected_port" "$PROXY_BINARY_PATH" "$REMOTE_PROXY_EXEC_PATH" "$PROXY_SOCKS_USER" "$PROXY_SOCKS_PASS"; then
            log_message "SUCCESS" "Proxy deployment successful on $server_ip_target:$selected_port."
        else
            log_message "ERROR" "Proxy deployment failed on $server_ip_target:$selected_port."
        fi
    fi
    log_message "INFO" "Finished processing server: $server_ip_raw"
done

log_message "INFO" "SOCKS5 proxy deployment script finished."
log_message "INFO" "=================================================="

exit 0
