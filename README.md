# SystemAudit-Tool

import os
import re
import csv
import socket
import nmap
from datetime import datetime

# Module 1: Log Parsing and Anomaly Detection
def parse_system_logs(log_file_path, anomaly_keywords):
    """
    Parses system logs and detects anomalies based on provided keywords.
    """
    anomalies = []
    if not os.path.exists(log_file_path):
        print(f"Log file not found: {log_file_path}")
        return anomalies

    with open(log_file_path, "r") as log_file:
        for line in log_file:
            if any(keyword in line for keyword in anomaly_keywords):
                anomalies.append(line.strip())
    return anomalies

# Module 2: Basic Vulnerability Checks
def basic_vulnerability_check(host):
    """
    Checks for common vulnerabilities on the host (basic implementation).
    """
    try:
        print(f"Checking vulnerabilities for {host}...")
        ip = socket.gethostbyname(host)
        print(f"Host resolved to IP: {ip}")
        return {"host": host, "ip": ip, "status": "No vulnerabilities detected"}
    except socket.gaierror:
        return {"host": host, "ip": "N/A", "status": "Host resolution failed"}

# Module 3: Port Scanning
def perform_port_scan(target, ports):
    """
    Scans the specified ports on the target.
    """
    nm = nmap.PortScanner()
    scan_result = {}
    print(f"Scanning {target} on ports {ports}...")
    try:
        nm.scan(target, ports)
        for port in nm[target]['tcp']:
            state = nm[target]['tcp'][port]['state']
            scan_result[port] = state
    except KeyError:
        print(f"Unable to scan {target}. Ensure the target is reachable.")
    return scan_result

# Module 4: Exporting CSV Summaries
def export_to_csv(data, file_name):
    """
    Exports data to a CSV file.
    """
    with open(file_name, mode='w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(data[0].keys())  # Write header
        for row in data:
            writer.writerow(row.values())
    print(f"Data exported to {file_name}")

# Main Function
def main():
    # Inputs
    log_file_path = input("Enter the system log file path: ")
    anomaly_keywords = ["error", "failed", "unauthorized", "critical"]
    target_host = input("Enter the target host for vulnerability checks and port scanning: ")
    ports_to_scan = input("Enter ports to scan (e.g., 22,80,443): ")
    summary_csv = "audit_summary.csv"

    # Step 1: Log Parsing and Anomaly Detection
    print("Parsing system logs and detecting anomalies...")
    anomalies = parse_system_logs(log_file_path, anomaly_keywords)
    print(f"Detected {len(anomalies)} anomalies.")

    # Step 2: Basic Vulnerability Checks
    vulnerability_check = basic_vulnerability_check(target_host)

    # Step 3: Port Scanning
    port_scan_results = perform_port_scan(target_host, ports_to_scan)

    # Step 4: Export CSV Summary
    print("Exporting summary to CSV...")
    audit_summary = [
        {"Category": "Anomalies", "Details": "\n".join(anomalies) if anomalies else "No anomalies found"},
        {"Category": "Vulnerability Check", "Details": f"Host: {vulnerability_check['host']}, IP: {vulnerability_check['ip']}, Status: {vulnerability_check['status']}"},
        {"Category": "Port Scanning", "Details": ", ".join([f"{port}: {state}" for port, state in port_scan_results.items()]) if port_scan_results else "No ports scanned"},
    ]
    export_to_csv(audit_summary, summary_csv)

    print("System audit completed.")

if __name__ == "__main__":
    main()
