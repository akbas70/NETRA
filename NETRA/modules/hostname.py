import socket

def get_hostname(ip):
    """Get hostname from IP, returns None if not resolvable."""
    try:
        return socket.gethostbyaddr(ip)[0]
    except:
        return None
