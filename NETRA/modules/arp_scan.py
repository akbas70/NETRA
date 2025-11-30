import subprocess

def get_mac(ip):
    try:
        output = subprocess.check_output(["arp", "-n", ip], text=True)
        for line in output.splitlines():
            if ip in line:
                parts = line.split()
                return parts[2]  # MAC
    except:
        return None
