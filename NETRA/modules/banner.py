import socket

def get_banner(ip, port, timeout=1):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        try:
            data = s.recv(256)
            if data:
                return data.decode(errors="ignore").strip()
        except:
            return ""
    except:
        return ""
    return ""
