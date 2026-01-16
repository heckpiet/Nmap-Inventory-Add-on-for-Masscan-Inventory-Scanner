#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Nmap Inventory Add-on for Masscan Inventory Scanner
Author: heckpiet
License: MIT

Description:
    This script acts as a secondary stage for the Masscan Inventory Scanner.
    It performs deep Nmap scans and provides two output types:
    1. Full Nmap standard output (human-readable technical log)
    2. Clustered CSV report (management/inventory level)
"""

import csv
import sys
import subprocess
import shutil
import xml.etree.ElementTree as ET
from pathlib import Path

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

    # Write to CSV with semicolon delimiter
    headers = ["IP Address", "DNS Name", "OS Family", "Services Cluster"]
    with csv_out.open('w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=headers, delimiter=';')
        writer.writeheader()
        writer.writerows(results)

def run_nmap_stage(masscan_csv: str) -> None:
    """Executes Nmap with multi-format output and post-processes the CSV."""
    check_dependencies()
    csv_path = Path(masscan_csv)
    
    if not csv_path.exists():
        print(f"[!] Input file not found: {csv_path}")
        return

    analysis_dir = csv_path.parent / "nmap_analysis"
    analysis_dir.mkdir(exist_ok=True)
    
    target_list = analysis_dir / "nmap_targets.tmp"
    output_base = analysis_dir / "nmap_results" # Base name for .xml and .nmap files
    final_csv = analysis_dir / "final_inventory_report.csv"

    # Extract IPs
    ips = []
    with csv_path.open('r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            if 'ip' in row: ips.append(row['ip'])

    if not ips:
        print("[!] No IPs found in the masscan CSV.")
        return

    target_list.write_text("\n".join(ips))
    print(f"[*] Prepared {len(ips)} hosts for Stage 2.")

    # Nmap Command:
    # -oX: XML format (for the script to parse)
    # -oN: Normal format (human-readable technical log)
    nmap_cmd = [
        "sudo", "nmap", "-A", "-R", "-T4", 
        "-iL", str(target_list), 
        "-oX", f"{output_base}.xml", 
        "-oN", f"{output_base}.nmap"
    ]
    
    print(f"[*] Executing Nmap Deep Scan...")
    try:
        subprocess.run(nmap_cmd, check=True)
        print("[*] Scan complete. Generating human-readable CSV...")
        
        # Parse the XML to create the clustered CSV
        parse_nmap_xml(Path(f"{output_base}.xml"), final_csv)
        
        print("\n" + "="*60)
        print("STAGE 2 COMPLETED")
        print(f"1. Technical Log: {output_base}.nmap")
        print(f"2. Inventory CSV: {final_csv}")
        print("="*60)
        
    except subprocess.CalledProcessError as e:
        print(f"[!] Nmap execution failed: {e}")
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python3 nmap_inventory_addon.py <path_to_inventory_hosts.csv>")
    else:
        run_nmap_stage(sys.argv[1])
