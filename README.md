# NETRA
NETRA: The concise Network Intelligence and Auditing Tool. Multi-functional utility suite for deep-dive network discovery, OUI analysis, and port scanning.


NETRA (Network Intelligence and Auditing Tool) is a lightweight, multi-functional utility suite designed for deep network analysis, discovery, and security auditing of local area networks (LANs) and Wi-Fi environments.

This multi-tool gathers the core functionalities of several complex network utilities into a single, efficient Command Line Interface (CLI) application. NETRA is optimized to run on Linux/Unix environments and is not intended for Windows users, due to its requirement for low-level packet access.

🛠️ Key Features

Functionality	Description
🌐 Host Discovery	Fast ARP and Ping scanning to quickly map active hosts (IP, MAC) on the local network segment.
🆔 OUI/Vendor Lookup	Analyzes the MAC Address of discovered devices to accurately identify the Manufacturer (Vendor).
🛡️ Port Scanning	Checks common TCP/UDP ports to determine which services are running on target hosts.
📶 Wi-Fi Audit & Analysis	Gathers information on surrounding Wi-Fi networks (SSID, signal strength, channel) for security auditing.

🚀 Installation and Setup

Prerequisites

    Python 3.x

    Linux/Unix Operating System (Required for low-level network access).

    Root/Administrator Privileges (Required for most scanning functions).

Setup Steps

Bash

# Clone the NETRA repository
git clone https://github.com/akbas70/NETRA.git
pip3 install scapy
cd Netra

Usage

Run the main application file using elevated privileges and follow the interactive menu prompts:
Bash

sudo python netra.py

📜 MIT License & Legal Disclaimer

⚠️ LEGAL DISCLAIMER AND USAGE RESTRICTIONS

NETRA IS PROVIDED STRICTLY FOR EDUCATIONAL PURPOSES, PERSONAL LEARNING, AND LEGITIMATE NETWORK SECURITY AUDITING.

The authors and contributors of NETRA DO NOT promote or condone any illegal or malicious activity. You are solely responsible for the way you use this tool. By using NETRA, you agree:

    You will only run the tool on networks you own and manage, or on networks where you have explicit, written authorization from the owner.

    The authors are NOT LIABLE for any misuse or damage caused by the use of this software.

This project is licensed under the MIT License. The full text of the license can be found in the LICENSE file in this repository.
