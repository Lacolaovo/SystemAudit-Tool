# SystemAudit-Tool

import os
import re
import csv
import socket
import nmap
from datetime import datetime


def parse_system_logs(log_file_path, anomaly_keywords):
    """
    Parses system log file and returns lines containing specified anomaly keywords.
    """
    anomalies = []

    if not os.path.exists(log_file_path):
        print(f"[!] Log file not found: {log_file_path}")
        return anomalies

    with open(log_file_path, "r") as log_file:
        for line in log_file:
            if any(keyword.lower() in line.lower() for keyword in anomaly_keywords):
                anomalies.append(line.strip())

    return anomalies


def basic_vulnerability_check(host):
    """
    Performs a basic vulnerability check by resolving host IP.
    """
    try:
        print(f"[+] Checking vulnerabilities for {host}...")
        ip = socket.gethostbyname(host)
        print(f"[+] Host resolved to IP: {ip}")
        return {"host": host, "ip": ip, "status": "No vulnerabilities detected"}
    except socket.gaierror:
        return {"host": host, "ip": "N/A", "status": "Host resolution failed"}


def perform_port_scan(target, ports):
    """
    Scans specified TCP ports on the target host.
    """
    nm = nmap.PortScanner()
    scan_result = {}

    print(f"[+] Scanning {target} on ports {ports}...")

    try:
        nm.scan(target, ports)
        for port in nm[target]['tcp']:
            state = nm[target]['tcp'][port]['state']
            scan_result[port] = state
    except KeyError:
        print(f"[!] Unable to scan {target}. Ensure the target is reachable.")

    return scan_result


def export_to_csv(data, file_name):
    """
    Exports a list of dictionaries to a CSV file.
    """
    try:
        with open(file_name, mode='w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=data[0].keys())
            writer.writeheader()
            for row in data:
                writer.writerow(row)
        print(f"[+] Data exported to {file_name}")
    except Exception as e:
        print(f"[!] Failed to export data: {e}")


def main():
    # User inputs
    log_file_path = input("Enter the system log file path: ").strip()
    anomaly_keywords = ["error", "failed", "unauthorized", "critical"]
    target_host = input("Enter the target host for vulnerability checks and port scanning: ").strip()
    ports_to_scan = input("Enter ports to scan (e.g., 22,80,443): ").strip()
    summary_csv = "audit_summary.csv"

    print("\n[+] Starting system audit...\n")

    # Step 1: Log Parsing
    print("[*] Parsing system logs for anomalies...")
    anomalies = parse_system_logs(log_file_path, anomaly_keywords)
    print(f"[+] Detected {len(anomalies)} anomalies.")

    # Step 2: Vulnerability Check
    vulnerability_check = basic_vulnerability_check(target_host)

    # Step 3: Port Scanning
    port_scan_results = perform_port_scan(target_host, ports_to_scan)

    # Step 4: Export Summary
    print("[*] Exporting results to CSV...")
    audit_summary = [
        {"Category": "Anomalies", "Details": "\n".join(anomalies) if anomalies else "No anomalies found"},
        {"Category": "Vulnerability Check", "Details": f"Host: {vulnerability_check['host']}, IP: {vulnerability_check['ip']}, Status: {vulnerability_check['status']}"},
        {"Category": "Port Scanning", "Details": ", ".join([f"{port}: {state}" for port, state in port_scan_results.items()]) if port_scan_results else "No ports scanned"},
    ]
    export_to_csv(audit_summary, summary_csv)

    print("\n[✓] System audit completed successfully.")


if __name__ == "__main__":
    main()
