# 📡 NETRA - Network Recon and Auditing Toolkit

**NETRA (Network Recon and Auditing Toolkit)** is a high-performance, multi-functional utility suite designed for deep network discovery, security auditing, and wireless analysis on local area networks (LANs) and Wi-Fi environments.

This multi-tool efficiently consolidates the core functionalities of several network utilities into a single, optimized **Command Line Interface (CLI)** application. It is built using Python, Scapy, and multi-threading for fast, reliable, and low-level network interactions.

---

## 🛠️ Key Features

| Functionality | Description | Technical Note |
| :--- | :--- | :--- |
| **🌐 Host Discovery** | Fast ARP and Ping scanning to quickly map active hosts (IP, MAC) on the local network segment. | Utilizes **Scapy's low-level packet crafting** for efficiency. |
| **⚡ Optimized Port Scanning** | Checks common TCP/UDP ports to determine running services and capture banners. | Employs **Multi-threading** (`ThreadPoolExecutor`) for **high-speed, concurrent port checks**. |
| **🆔 OUI/Vendor Lookup** | Analyzes the MAC Address of discovered devices to accurately identify the Manufacturer (Vendor). | Requires an `oui.txt` file for local, offline lookup. |
| **🛡️ Wi-Fi Auditing & Stress Testing** | Advanced tools for interface mode management, network reconnaissance, and **testing resilience against deauthentication** attacks and rogue access points. | Requires root privileges and interface must be in **Monitor Mode** for many functions. |

---

## 🚀 Installation and Setup

### Prerequisites

* **Python 3.x**
* **Linux/Unix Operating System** (Required for low-level network access and Scapy integration).
* **Root/Administrator Privileges** (Required for ARP scanning, Wi-Fi auditing, and interface manipulation).

### Setup Steps

```bash
# Clone the NETRA repository
git clone [https://github.com/akbas70/NETRA.git](https://github.com/akbas70/NETRA.git)
cd NETRA

# Install required libraries, including Scapy
pip3 install scapy

# Get the OUI database for vendor lookup (optional, but recommended)
# You may need to manually place or update an 'oui.txt' file.

Usage

Run the main application file using elevated privileges and specify the command:
Bash

sudo python netra.py [command] -h

Example Usage:

    Port Scan: sudo python netra.py scan -t 192.168.1.1 --ports 1-1000

    ARP Scan: sudo python netra.py wireless netscan -i eth0 -r 192.168.1.0/24

📜 MIT License & Legal Disclaimer

⚠️ LEGAL DISCLAIMER AND RESPONSIBLE USAGE

NETRA IS PROVIDED STRICTLY FOR EDUCATIONAL PURPOSES, PERSONAL LEARNING, AND LEGITIMATE NETWORK SECURITY AUDITING.

The authors and contributors of NETRA DO NOT promote or condone any illegal or malicious activity. You are solely responsible for the way you use this tool. By using NETRA, you agree:

    You will only run the tool on networks you own and manage, or on networks where you have explicit, written authorization from the owner.

    The advanced wireless tools are designed to test the security and configuration resilience of your own network infrastructure.
