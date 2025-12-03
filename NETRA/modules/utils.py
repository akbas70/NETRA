import socket
import subprocess
import sys

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


def log(msg, color=C.END):
    """Print a colored log message."""
    print(f"{color}{msg}{C.END}")


def get_banner(host: str, port: int, timeout: float = 1.0) -> str | None:
    """Try grabbing a service banner from an open TCP port."""
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((host, port))
        banner = s.recv(1024).decode(errors="ignore").strip()
        s.close()
        return banner if banner else None
    except Exception:
        return None


def identify_device(open_ports: list[int], banner_text: str) -> str:
    """
    Basic fingerprinting based on open ports + captured banners.
    """
    fp = " ".join(str(p) for p in open_ports) + banner_text.lower()

    if "ssh" in fp or 22 in open_ports:
        return "Linux/Unix Host"
    if 80 in open_ports or "http" in fp or "server" in fp:
        return "Web Server / Router"
    if 3389 in open_ports:
        return "Windows Server / Desktop"
    if 21 in open_ports or "ftp" in fp:
        return "FTP Server Device"
    if 445 in open_ports or 139 in open_ports:
        return "SMB / Windows Network"

    return "Unknown Device"

def resolve_hostname(ip: str) -> str | None:
    """Attempt to resolve the hostname for a given IP address."""
    try:
        # Note: socket.gethostbyaddr can sometimes be slow or fail in complex network setups
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return None
    except Exception:
        return None
    
def os_resolve_hostname(ip: str) -> str | None:
    """Attempt to resolve the hostname for a given IP address using OS utilities (e.g., nslookup)."""
    try:
        # Sử dụng subprocess thay vì socket để tra cứu DNS/NetBIOS
        result = subprocess.run(['nslookup', ip], capture_output=True, text=True, timeout=2)
        output = result.stdout
        for line in output.splitlines():
            if 'name =' in line:
                return line.split('=')[1].strip().rstrip('.')
        return None
    except Exception:
        return None
    
def suggest_next_steps(target: str, mac: str | None, open_ports: list[int], vendor: str | None):
    """Suggest next steps based on gathered info."""
    log("\n[+] Suggested Next Steps:", C.C)
    
    if not mac:
        log(f"- {C.Y}MAC address not found.{C.END} Consider using ARP scanning to retrieve it (if on LAN).", C.Y)
    
    if not open_ports:
        log(f"- {C.R}No open ports detected.{C.END} Consider using a wider port range (e.g., --ports 1-65535).", C.R)
    

    else:
        log(f"- Open ports detected: {C.G}{', '.join(map(str, open_ports))}{C.END}. Consider service enumeration on these ports.", C.G)
        
        if 22 in open_ports:
            log("- Port 22 (SSH) is open. Consider using tools like 'ssh-audit' for SSH service enumeration.", C.G)
            if 80 in open_ports or 443 in open_ports:
                log("- Ports 80/443 are also open. Consider checking for {C.G}web interfaces{C.END}.", C.G)
        
        if 80 in open_ports:
            log("- Port 80 (HTTP) is open. Consider using tools like 'nikto' or 'dirb' for {C.G}web server enumeration{C.END}.", C.G)
        

        if 445 in open_ports or 139 in open_ports:
            log("- SMB ports (445/139) are open. Consider using 'enum4linux' or 'smbclient' for SMB enumeration.", C.G)
            

    if vendor:
        log(f"- Detected vendor: {C.B}{vendor}{C.END}. Research common vulnerabilities for this vendor/device type.", C.B)
    
    log("- Always ensure to document your findings and proceed ethically.", C.C)
