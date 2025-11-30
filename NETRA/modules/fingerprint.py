def identify_device(open_ports, banner):
    pset = set(open_ports)

    if 554 in pset:
        return "IP Camera / DVR"

    if 22 in pset and "OpenSSH" in banner:
        return "Linux Device"

    if 445 in pset:
        return "Windows PC / SMB Device"

    if 80 in pset:
        if "tp-link" in banner.lower():
            return "TP-Link Router"
        if "microhttpd" in banner.lower():
            return "IoT Device"
        return "Web Server"

    if 8080 in pset:
        return "Smart TV / Media Server"

    return "Unknown Device"
