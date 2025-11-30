import socket
import concurrent.futures
from typing import List, Tuple

def connect_port(host: str, port: int, timeout: float = 0.8) -> bool:
    """Try to connect to a TCP port. Returns True if successful."""
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False

def scan_ports(host: str, ports: List[int], timeout: float = 0.8, workers: int = 50) -> List[Tuple[int, bool]]:
    """Scan a list of TCP ports on a host using multiple threads."""
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {executor.submit(connect_port, host, port, timeout): port for port in ports}
        for fut in concurrent.futures.as_completed(futures):
            port = futures[fut]
            try:
                is_open = fut.result()
            except Exception:
                is_open = False
            results.append((port, is_open))
    results.sort()
    return results
