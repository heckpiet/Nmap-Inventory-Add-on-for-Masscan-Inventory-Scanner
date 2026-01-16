#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nmap Inventory Add-on for Masscan Inventory Scanner
Author: heckpiet
License: MIT

Description:
    This script acts as a secondary stage for the Masscan Inventory Scanner.
    It takes the aggregated 'inventory_hosts.csv', performs deep Nmap scans 
    (OS fingerprinting, Service detection, DNS resolution), and clusters 
    the results into a clean, human-readable inventory.
"""

import csv
import sys
import subprocess
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime

def check_dependencies() -> None:
    """Check if required system binaries are available."""
    if shutil.which("nmap") is None:
        print("[!] Error: 'nmap' not found in PATH. Please install it.")
        sys.exit(1)

def parse_nmap_xml(xml_path: Path, csv_out: Path) -> None:
    """
    Parses Nmap XML output and generates a clustered CSV report.
    Groups all ports and services by their respective IP address.
    """
    if not xml_path.exists():
        print(f"[!] Error: XML file {xml_path} missing.")
        return

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except ET.ParseError as e:
        print(f"[!] XML Parsing Error: {e}")
        return

    results = []

    for host in root.findall('host'):
        # Extract IP (IPv4)
        addr = host.find("address[@addrtype='ipv4']")
        ip = addr.get('addr') if addr is not None else "Unknown"

        # Extract Hostnames (DNS)
        hostnames = [hn.get('name') for hn in host.findall(".//hostname") if hn.get('name')]
        dns_names = ", ".join(set(hostnames)) if hostnames else "N/A"

        # Extract Operating System
        os_match = host.find(".//osmatch")
        os_info = os_match.get('name') if os_match is not None else "Undetermined"

        # Cluster Services
        service_list = []
        for port in host.findall(".//port"):
            state_node = port.find('state')
            if state_node is not None and state_node.get('state') == 'open':
                p_id = port.get('portid')
                p_proto = port.get('protocol')
                svc_node = port.find('service')
                
                svc_name = svc_node.get('name') if svc_node is not None else "unknown"
                svc_prod = svc_node.get('product', '') if svc_node is not None else ""
                svc_ver = svc_node.get('version', '') if svc_node is not None else ""
                
                full_svc = f"{p_id}/{p_proto} ({svc_name}: {svc_prod} {svc_ver})".strip()
                service_list.append(full_svc)

        results.append({
            "IP Address": ip,
            "DNS Name": dns_names,
            "OS Family": os_info,
            "Services Cluster": " | ".join(service_list) if service_list else "No open ports"
        })

    # Write to CSV with semicolon delimiter for European Excel compatibility
    headers = ["IP Address", "DNS Name", "OS Family", "Services Cluster"]
    with csv_out.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers, delimiter=';')
        writer.writeheader()
        writer.writerows(results)

def run_nmap_stage(masscan_csv: str) -> None:
    """Executes the Nmap scanning logic based on Masscan output."""
    check_dependencies()
    csv_path = Path(masscan_csv)
    
    if not csv_path.exists():
        print(f"[!] Input file not found: {csv_path}")
        return

    # Define paths relative to the masscan output directory
    analysis_dir = csv_path.parent / "nmap_analysis"
    analysis_dir.mkdir(exist_ok=True)
    
    target_list = analysis_dir / "nmap_targets.tmp"
    xml_output = analysis_dir / "nmap_raw_data.xml"
    final_report = analysis_dir / "final_inventory_report.csv"

    # Extract IPs from Masscan CSV
    ips = []
    with csv_path.open('r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if 'ip' in row: ips.append(row['ip'])

    if not ips:
        print("[!] No IPs found to scan.")
        return

    target_list.write_text("\n".join(ips))
    print(f"[*] Prepared {len(ips)} hosts for deep inspection.")

    # Execution of Nmap
    # -A: OS/Service detection & Script scanning
    # -R: Resolve DNS for all targets
    nmap_cmd = ["sudo", "nmap", "-A", "-R", "-T4", "-iL", str(target_list), "-oX", str(xml_output)]
    
    print(f"[*] Starting Nmap stage (Stage 2)...")
    try:
        subprocess.run(nmap_cmd, check=True)
        print("[*] Scan finished. Parsing results...")
        parse_nmap_xml(xml_output, final_report)
        print(f"[SUCCESS] Deep inventory created: {final_report}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Nmap failed: {e}")
    except KeyboardInterrupt:
        print("\n[!] User aborted.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 nmap_inventory_addon.py <path_to_inventory_hosts.csv>")
    else:
        run_nmap_stage(sys.argv[1])
