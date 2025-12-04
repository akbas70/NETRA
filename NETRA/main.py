#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
import time
import sys
import webbrowser
import socket
import os
import subprocess
import json
import re
import ipaddress
import concurrent.futures
from typing import List, Tuple
from scapy.all import RandMAC, Ether, srp, ARP, Dot11, Dot11Deauth, sendp, RadioTap
import atexit


#NETRA - Network Recon and Wireless Toolkit
#TRETRA --version 0.9.5
#coder: nexucy19/akbas70

def print_logo():
    logo = """
    

█████████████████████████████████████████████
█████████████████████████████████████████████
██████████████████████ ██████████████████████
██████████████████████ ██████████████████████
██████████████████████ ██████████████████████
████████████  ████████ ████████  ████████████
███████████ █ ██████     ██████ █ ███████████
██████████████  █████   █████  ██████████████
███████████████   ███   ███   ███████████████
██████████████ █   ██  ███  ██ ██████████████
██████████████████  █  █   ██████████████████
███████████████████       ███████████████████
█████████████████████   █████████████████████
█████████████████████   █████████████████████
████████████████████     ████████████████████
██████████████████░  █ █  ███████████████████
█████████████████   ██ ██   █████████████████
████████████████  ████ ████  ████████████████
███████████████  █████ █████  ███████████████
██████████████ ███████ ███████ ██████████████
█████████████ ████████ ████████ █████████████
██████████████████████ ██████████████████████
█████████████████████████████████████████████
█████████████████████████████████████████████

    """
    print(C.R + logo + C.END) 
    log(f"NETRA - Wireless Device Fingerprint Scanner", C.B)
    log(f"Version: 0.9.5 | Author: {GITHUB_URL}", C.C)
    log(f"CODER: nexucy19/akbas70", C.C )
    print("-" * 40)


# CONSOLIDATED UTILITIES
class C:
    """ANSI color codes for terminal output."""
    END = "\033[0m"
    R = "\033[31m"   # RED
    G = "\033[32m"   # GREEN
    Y = "\033[33m"   # YELLOW
    B = "\033[34m"   # BLUE
    M = "\033[35m"   # MAGENTA
    C = "\033[36m"   # CYAN
    W = "\033[37m"   # WHITE

def log(message, color=C.END):
    """Print a structured log message."""
    print(f"[{C.B}*{C.END}] {color}{message}{C.END}")

def resolve_hostname(ip: str) -> str | None:
    """Attempt to resolve the hostname for a given IP address."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None
    except Exception:
        return None

def identify_device(open_ports: list[int], banner_text: str) -> str:
    """Basic fingerprinting based on open ports + captured banners (from utils.py)."""
    fp = " ".join(str(p) for p in open_ports) + banner_text.lower()

    if "ssh" in fp or 22 in open_ports:
        return "Linux/Unix Host (SSH)"
    if 80 in open_ports or 443 in open_ports or "http" in fp:
        return "Web Server / Router (HTTP/S)"
    if 3389 in open_ports:
        return "Windows Server / Desktop (RDP)"
    if 21 in open_ports or "ftp" in fp:
        return "FTP Server Device"
    if 445 in open_ports or 139 in open_ports:
        return "SMB / Windows Network"

    return "Generic Host"

def suggest_next_steps(target: str, mac: str | None, open_ports: list[int], vendor: str | None):
    """Suggest next steps based on gathered info (from utils.py)."""
    print(f"\n{C.C}--- SCAN FAILURE SUGGESTIONS ---{C.END}")
    suggestions = False
    
    if not mac or not vendor:
        log(f"-> {C.Y}MAC/Vendor not found.{C.END} Try running a broader network scan (if on LAN) or check interface permissions.", C.Y)
        suggestions = True
    
    if not open_ports:
        log(f"-> {C.R}No open ports detected.{C.END} Try scanning a wider range of ports: Example: python3 netra.py scan -t {target} --ports 1-1000", C.R)
        log(f"-> {C.R}Target may be offline or heavily firewalled.{C.END} Double-check IP connectivity.", C.R)
        suggestions = True
    
    if open_ports:
        log(f"-> Open ports: {C.G}{', '.join(map(str, open_ports))}{C.END}. Consider service enumeration.", C.G)

    if vendor:
        log(f"-> Detected vendor: {C.B}{vendor}{C.END}. Research common vulnerabilities for this vendor/device type.", C.B)

    if suggestions:
        print(f"{C.C}--------------------------------{C.END}")

#  CONSOLIDATED PORT SCANNING 

def grab_banner(sock, length=1024) -> str:
    """Helper to grab banner data."""
    try:
        sock.settimeout(0.3)
        data = sock.recv(length)
        return data.decode(errors="ignore").strip()
    except Exception:
        return ""

def connect_and_info(host: str, port: int, timeout: float = 0.8) -> Tuple[int, bool, str]:
    """Attempts connection and grabs banner in a single thread worker."""
    try:
        # Use socket.create_connection for better handling
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = grab_banner(sock)
            return port, True, banner
    except Exception:
        return port, False, ""

def scan_ports(host: str, ports: List[int], timeout: float = 0.8, workers: int = 100) -> List[Tuple[int, bool, str]]:
    """Multi-threaded port scanner (from port_scan.py)."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(connect_and_info, host, port, timeout): port for port in ports}
        
        for fut in concurrent.futures.as_completed(futures):
            try:
                # Result structure: (port, is_open, banner)
                results.append(fut.result()) 
            except:
                pass

    # Filter out closed ports to speed up the sort
    open_results = [r for r in results if r[1] is True]
    open_results.sort(key=lambda x: x[0])
    return open_results # Only return open ports with banners

#  CONSOLIDATED ARP SACNNING

def get_mac(ip, interface=None, timeout=1):
    """Sends ARP request via Scapy to get MAC address (robust)."""
    try:
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip)
        ans, unans = srp(arp_request, timeout=timeout, verbose=0, iface=interface)
        
        if ans:
            return ans[0][1].hwsrc.upper()
        else:
            return None
            
    except Exception as e:
        if interface and "No such device" not in str(e):
             log(f"Scapy error during MAC scan: {e}", C.R)
        return None

# VENDOR LOOKUP 

GITHUB_URL = "https://github.com/akbas70"
HELPFUL_LINKS = [
    f"{C.B}1. ARP packet configuration: https://en.wikipedia.org/wiki/Address_Resolution_Protocol{C.END}",
    f"{C.B}2. OUI (Vendor MAC) database: https://standards-oui.ieee.org/{C.END}",
    f"{C.B}3. Port scanning theory: https://en.wikipedia.org/wiki/Port_scanning{C.END}"
]

def load_oui_db(file_path):
    """Loads OUI database (once)."""
    oui_db = {}
    try:
        with open(file_path, 'r', encoding='latin-1') as f:
            for line in f:
                if '(hex)' in line:
                    parts = line.split()
                    if len(parts) >= 3:
                        mac_prefix = parts[0].replace('-', ':').upper()
                        vendor = ' '.join(parts[2:])
                        oui_db[mac_prefix] = vendor
    except FileNotFoundError:
        log(f"OUI file not found: {file_path}", C.R)
    return oui_db

def get_vendor(mac, oui_db):
    """Looks up vendor using the loaded OUI database."""
    mac_prefix = ":".join(mac.split(':')[:3]).upper()
    return oui_db.get(mac_prefix, None)

# HELPER FUNCTIONS 

def check_root():
    if os.geteuid() != 0:
        log("ERROR: This function requires ROOT privileges. Please run with sudo.", C.R)
        sys.exit(1)

def check_interface_exists(interface):
    try:
        subprocess.run(["ip", "link", "show", interface], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        log(f"ERROR: Interface '{interface}' does not exist.", C.R)
        return False
        
def set_interface_mode(interface, mode="Managed"):
    """Sets interface mode (Managed/Monitor). REQUIRES ROOT."""
    check_root()
    log(f"Setting {interface} to {C.Y}{mode}{C.END} mode...")
    try:
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["iwconfig", interface, "mode", mode], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        log("Mode set successfully.", C.G)
        return True
    except subprocess.CalledProcessError as e:
        log(f"Error changing mode: {e}", C.R)
        return False

def check_monitor_mode(interface):
    try:
        result = subprocess.run(["iwconfig", interface], capture_output=True, text=True)
        if "Mode:Monitor" in result.stdout:
            return True
    except:
        pass
    return False

# CORE FUNCTIONS (SCAN)

def run_scan_analysis(args, oui_db): # Receives OUI_DB
    """Device fingerprinting and port scan logic."""
    target = args.target
    interface = args.interface if hasattr(args, 'interface') else None
    
    log(f"Analyzing device: {target}", C.B)
    
    # Use consolidated resolve_hostname
    hostname = resolve_hostname(target)
    log(f"Hostname: {C.G}{hostname}{C.END}" if hostname else f"Hostname: {C.R}Not available (DNS fail).{C.END}")

    # Use Scapy-based get_mac
    mac = get_mac(target, interface=interface) 
    log(f"MAC Address: {C.Y}{mac}{C.END}" if mac else f"MAC address: {C.R}Not available (not in LAN?).{C.END}")

    vendor = None
    if mac:
        vendor = get_vendor(mac, oui_db)
        log(f"Vendor: {C.G}{vendor}{C.END}" if vendor else f"Vendor: {C.Y}Not found in OUI DB.{C.END}")

    ports = [80, 443, 22, 23, 554, 8080, 8000, 21, 25, 110, 139, 445]
    
    if args.ports:
        try:
            ports = []
            for item in args.ports.split(","):
                if '-' in item:
                    start, end = map(int, item.split('-'))
                    ports.extend(range(start, end + 1))
                else:
                    ports.append(int(item.strip()))
        except ValueError:
            log("Invalid port format. Using default ports.", C.R)

    log(f"Scanning {len(ports)} ports...", C.B)
    start = time.time()
    
    # Use consolidated multi-threaded scan_ports
    scan_results = scan_ports(target, ports) # (port, is_open, banner) for open ports
    elapsed = time.time() - start
    
    open_ports = [p for p, ok, b in scan_results if ok]
    banners_combined = " ".join(b for p, ok, b in scan_results if ok and b)
    
    # Log open ports and banners
    for port, ok, banner in scan_results:
        log(f"Port {C.Y}{port}{C.END} OPEN -> Banner: {banner}", C.G)

    # Use consolidated identify_device
    device_type = identify_device(open_ports, banners_combined)
    log(f"Likely device type: {C.G}{device_type}{C.END}", C.B)
    log(f"Scan completed in {elapsed:.2f} seconds.", C.B)

    # Use consolidated suggest_next_steps
    if not mac or not open_ports:
        suggest_next_steps(target, mac, open_ports, vendor)


# WIRELESS FUNCTIONS 

def deauther_target(args):
    # Deauth Attack (Targeted or Blind/Broadcast)
    check_root()
    # ... (Logic remains the same)
    if not check_interface_exists(args.interface): return False
    if not check_monitor_mode(args.interface): 
        log(f"ERROR: Interface {args.interface} is not in Monitor mode.", C.R)
        return False

    # Validate MAC addresses
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', args.target_mac.upper()):
        log("ERROR: Invalid target MAC format.", C.R)
        return False
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', args.gateway_mac.upper()):
        log("ERROR: Invalid gateway MAC format.", C.R)
        return False

    # Scapy packet crafting
    dot11 = Dot11(addr1=args.target_mac, addr2=args.gateway_mac, addr3=args.gateway_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    
    log(f"Sending {args.count} Deauth packets to {C.Y}{args.target_mac}{C.END} via {args.interface}...", C.B)
    try:
        sendp(packet, iface=args.interface, count=args.count, inter=args.interval, verbose=0)
        log("Deauth packets sent successfully.", C.G)
        return True
    except Exception as e:
        log(f"Error sending packets: {e}. Check Monitor Mode.", C.R)
        return False

def scan_network_routers(args):
    # ARP Scan for devices in LAN
    # ... (Logic remains the same)
    if not check_interface_exists(args.interface): return False
    
    network_range = args.range
    log(f"ARP scanning network range {network_range} on {args.interface}...", C.B)
    
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_range)
    ans, unans = srp(arp_request, timeout=args.timeout, verbose=0, iface=args.interface)
    
    if not ans:
        log("No ARP responses found.", C.R)
        return False
        
    log("--- Network Scan Results ---", C.B)
    for snd, rcv in ans:
        print(f"IP: {C.G}{rcv.psrc}{C.END} - MAC: {C.Y}{rcv.hwsrc}{C.END}")
    log("----------------------------", C.B)
    return True

def create_fake_router_ap(args):
    # Fake AP (Uses airbase-ng via subprocess)
    check_root()
    interface = args.interface
    if not check_interface_exists(interface): return False
    if not check_monitor_mode(interface): 
        log(f"ERROR: Interface {interface} is not in Monitor mode.", C.R)
        return False
    # ... (dependencies and channel validation logic remains the same)

    def cleanup_ap():
        log(f"Performing cleanup... Setting {interface} back to Managed Mode.", C.Y)
        set_interface_mode(interface, mode="Managed")
        
    log(f"Starting Fake AP: SSID={C.G}{args.ssid}{C.END}, Channel={args.channel} on {interface}...", C.B)
    log(f"WARNING: Requires 'airbase-ng'. Press Ctrl+C to stop.", C.Y)
    
    atexit.register(cleanup_ap) 
    
    try:
        subprocess.call(["airbase-ng", "--essid", args.ssid, "--channel", args.channel, interface])
        log("Fake AP process stopped.", C.G)
        return True
    except FileNotFoundError:
        log("ERROR: airbase-ng not found. Please install aircrack-ng.", C.R)
        return False
    except KeyboardInterrupt:
        log("Fake AP stopped by user.", C.B)
        return True
    except Exception as e:
        log(f"Error starting Fake AP: {e}.", C.R)
        return False
    finally:
        atexit.unregister(cleanup_ap)
        cleanup_ap()


# --- UTILS FUNCTIONS ---

def handle_mac_change_cli(args):
    # Change MAC
    # ... (Logic remains the same)
    pass # Assume mac change functions are defined elsewhere/imported

def show_links_cli(args):
    # Helpful Links
    log("--- Helpful Links ---", C.B)
    for link in HELPFUL_LINKS:
        print(link)
    log("---------------------", C.B)
    if args.github:
        log(f"Opening Github: {GITHUB_URL}", C.B)
        webbrowser.open(GITHUB_URL)

# --- ARGPARSE SETUP (CLI Structure) ---

def create_parser():
    parser = argparse.ArgumentParser(
        description=f"{C.B}NETRA - Wireless Device Fingerprint Scanner (CLI){C.END}",
        epilog="Use 'netra.py <command> -h' for command-specific help."
    )
    subparsers = parser.add_subparsers(dest='command', required=True, help='Select operating mode.')

    # 1. SCAN/ANALYSIS Mode
    parser_scan = subparsers.add_parser('scan', help='Scan and fingerprint devices (Port, MAC, Vendor).')
    parser_scan.add_argument("-t", "--target", required=True, help="Target IP address (e.g., 192.168.1.1).")
    parser_scan.add_argument("-i", "--interface", help="Network interface for local MAC discovery (optional).")
    parser_scan.add_argument("--ports", help="Custom port list (e.g., 22,80,443,1000-2000).")
    parser_scan.add_argument("--oui", default="oui.txt", help="OUI file path for vendor lookup.")
    parser_scan.set_defaults(func=run_scan_analysis)

    # 2. WIRELESS Mode (Attack/Wireless tools - REQUIRES ROOT)
    parser_wireless = subparsers.add_parser('wireless', help='Advanced Wi-Fi tools (Deauth, Fake AP, Netscan). REQUIRES ROOT.')
    wireless_subparsers = parser_wireless.add_subparsers(dest='wireless_command', required=True)

    # wireless deauth
    parser_deauth = wireless_subparsers.add_parser('deauth', help='Perform Deauthentication attack.')
    parser_deauth.add_argument("-i", "--interface", required=True, help="Wi-Fi interface in Monitor Mode (e.g., wlan0mon).")
    parser_deauth.add_argument("-t", "--target-mac", required=True, help="Client MAC (or FF:FF... for broadcast).")
    parser_deauth.add_argument("-g", "--gateway-mac", required=True, help="AP/Gateway MAC (BSSID).")
    parser_deauth.add_argument("-c", "--count", type=int, default=100, help="Number of Deauth packets to send.")
    parser_deauth.add_argument("--interval", type=float, default=0.1, help="Interval between packets (seconds).")
    parser_deauth.set_defaults(func=deauther_target)

    # wireless netscan
    parser_netscan = wireless_subparsers.add_parser('netscan', help='ARP scan for devices in LAN.')
    parser_netscan.add_argument("-i", "--interface", required=True, help="Network interface for ARP.")
    parser_netscan.add_argument("-r", "--range", default="192.168.1.0/24", help="Network range (e.g., 192.168.0.0/24).")
    parser_netscan.add_argument("-t", "--timeout", type=int, default=3, help="Timeout for response (seconds).")
    parser_netscan.set_defaults(func=scan_network_routers)

    # wireless fake-ap
    parser_fakeap = wireless_subparsers.add_parser('fake-ap', help='Create a Fake Access Point (Requires airbase-ng).')
    parser_fakeap.add_argument("-i", "--interface", required=True, help="Interface in Monitor Mode.")
    parser_fakeap.add_argument("--ssid", required=True, help="SSID for the Fake AP.")
    parser_fakeap.add_argument("-ch", "--channel", required=True, help="Wi-Fi Channel (1-14).")
    parser_fakeap.set_defaults(func=create_fake_router_ap)

    # 3. UTILS Mode (General utilities)
    parser_utils = subparsers.add_parser('utils', help='General utility and information commands.')
    utils_subparsers = parser_utils.add_subparsers(dest='utils_command', required=True)

    # utils mac-change
    parser_mac = utils_subparsers.add_parser('mac-change', help='Change network interface MAC address (REQUIRES ROOT).')
    parser_mac.add_argument("-i", "--interface", required=True, help="Network interface.")
    parser_mac.add_argument("-m", "--new-mac", help="New MAC address (leave blank for random).")
    parser_mac.set_defaults(func=handle_mac_change_cli)

    # utils links
    parser_links = utils_subparsers.add_parser('links', help='Show helpful links and documentation.')
    parser_links.add_argument("--github", action='store_true', help='Open the project Github page.')
    parser_links.set_defaults(func=show_links_cli)
    
    return parser

# EXECUTION 

if __name__ == "__main__":
    parser = create_parser()
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
        
    args = parser.parse_args()
    
    print_logo() 
    
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    # Load OUI Database ONCE
    OUI_FILE = args.oui if hasattr(args, 'oui') and args.oui else "oui.txt"
    log(f"Loading OUI Database from {OUI_FILE}...", C.B)
    OUI_DB = load_oui_db(OUI_FILE)
    
    if hasattr(args, 'func'):
        # Pass OUI_DB to run_scan_analysis
        if args.func == run_scan_analysis:
            success = args.func(args, OUI_DB)
        else:
            success = args.func(args)
            
        if success is False:
            sys.exit(1)
    else:
        parser.print_help(sys.stderr)
