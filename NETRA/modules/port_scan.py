import socket
import concurrent.futures
from typing import List, Tuple

def grab_banner(sock, length=1024) -> str:
    try:
        sock.settimeout(0.3)
        data = sock.recv(length)
        return data.decode(errors="ignore").strip()
    except Exception:
        return ""

def connect_and_info(host: str, port: int, timeout: float = 0.8) -> Tuple[int, bool, str]:
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            banner = grab_banner(sock)
            return port, True, banner
    except Exception:
        return port, False, ""

def scan_ports(host: str, ports: List[int], timeout: float = 0.8, workers: int = 100) -> List[Tuple[int, bool, str]]:
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(connect_and_info, host, port, timeout): port for port in ports}
        
        for fut in concurrent.futures.as_completed(futures):
            try:
                port, is_open, banner = fut.result()
                results.append((port, is_open, banner)) 
            except:
                pass

    results.sort(key=lambda x: x[0])
    return results

def common_ports() -> List[int]:
    return [
        20, 21, 22, 23, 25, 53, 67, 68, 69, 80,
        110, 111, 123, 135, 137, 138, 139, 143,
        161, 162, 179, 443, 445, 514, 520, 587,
        631, 636, 993, 995, 1080, 1194, 1433,
        1521, 1723, 2049, 2082, 2083, 3306,
        3389, 5432, 5900, 6379, 8080, 8443,
        9000, 9090
    ]

