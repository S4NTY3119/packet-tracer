"""
███████╗       ██╗██╗ ███╗   ██╗ ████████╗ ██╗   ██╗
██╔════╝     ██╔╝ ██║ ████╗  ██║ ╚══██╔══╝ ╚██╗ ██╔╝
███████╗   ██╔╝   ██║ ██╔██╗ ██║    ██║     ╚████╔╝ 
╚════██║  ██████████║ ██║╚██╗██║    ██║      ╚██╔╝  
███████║  ╚═══════██║ ██║ ╚████║    ██║       ██║   
╚══════╝          ╚═╝ ╚═╝  ╚═══╝    ╚═╝       ╚═╝
find victims, shit crazyyy
"""
import sys
import socket
import platform
import subprocess
import re
import uuid

try:
    from scapy.all import conf, Ether, ARP, srp, get_if_hwaddr
    SCAPY_AVAILABLE = True
except ImportError:
    conf = None
    Ether = None
    ARP = None
    srp = None
    get_if_hwaddr = None
    SCAPY_AVAILABLE = False


def get_local_ip(override_ip=None):
    if override_ip:
        return override_ip.strip()
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def get_local_mac():
    if conf and get_if_hwaddr:
        try:
            mac = get_if_hwaddr(conf.iface)
            if mac and mac != "00:00:00:00:00:00":
                return mac.lower()
        except Exception:
            pass

    if Ether:
        try:
            mac = Ether().src
            if mac and mac != "00:00:00:00:00:00":
                return mac.lower()
        except Exception:
            pass

    try:
        mac_hex = f"{uuid.getnode():012x}"
        return ":".join(mac_hex[i:i+2] for i in range(0, 12, 2)).lower()
    except Exception:
        return "00:00:00:00:00:00"


def get_default_gateway(override_gw=None):
    if override_gw:
        return override_gw.strip()

    os_type = platform.system().lower()

    if conf:
        try:
            gw = conf.route.route("0.0.0.0")[2]
            if gw and gw != "0.0.0.0":
                return gw
        except Exception:
            pass

    if "windows" in os_type:
        try:
            output = subprocess.check_output("route print 0.0.0.0", shell=True).decode('utf-8', errors='ignore')
            for line in output.splitlines():
                if "0.0.0.0" in line:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                        return parts[2]
        except Exception:
            pass

    try:
        output = subprocess.check_output("ip route show default", shell=True).decode('utf-8', errors='ignore')
        match = re.search(r"default via ([\d\.]+)", output)
        if match:
            return match.group(1)
    except Exception:
        pass

    local_ip = get_local_ip()
    if local_ip != "127.0.0.1":
        parts = local_ip.split(".")
        return f"{parts[0]}.{parts[1]}.{parts[2]}.1"

    return "192.168.1.1"


def get_subnet_cidr(local_ip=None):
    if not local_ip:
        local_ip = get_local_ip()
    if local_ip == "127.0.0.1":
        return "192.168.1.0/24"
    parts = local_ip.split(".")
    return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"


def get_system_arp_table():
    arp_map = {}
    try:
        output = subprocess.check_output("arp -a", shell=True).decode('utf-8', errors='ignore')
        for line in output.splitlines():
            match = re.search(
                r"(\b\d{1,3}(?:\.\d{1,3}){3}\b)\s+([0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2}[:-][0-9a-fA-F]{2})",
                line
            )
            if match:
                ip = match.group(1)
                mac = match.group(2).replace("-", ":").lower()
                if mac not in ["ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"]:
                    arp_map[ip] = mac
    except Exception:
        pass
    return arp_map


def scan_network(custom_subnet=None):
    local_ip = get_local_ip()
    gateway_ip = get_default_gateway()
    subnet = custom_subnet if custom_subnet else get_subnet_cidr(local_ip)

    print(f"\n[*] Scanning subnet: {subnet}")
    print(f"[*] Host IP: {local_ip} | Gateway: {gateway_ip}\n")
    print(f"{'#':<3} {'IP ADDRESS':<16} {'MAC ADDRESS':<19} {'ROLE / HOSTNAME'}")
    print("-" * 65)

    discovered = {}

    if srp and Ether and ARP:
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)
            ans, _ = srp(pkt, timeout=2.5, retry=1, verbose=0)
            for _, rcv in ans:
                ip = rcv.psrc
                mac = rcv.hwsrc.lower()
                discovered[ip] = {"mac": mac}
        except Exception:
            pass

    sys_arp = get_system_arp_table()
    for ip, mac in sys_arp.items():
        if ip not in discovered:
            discovered[ip] = {"mac": mac}

    if local_ip not in discovered:
        discovered[local_ip] = {"mac": get_local_mac()}

    devices = []
    index = 1

    def ip_sort_key(ip_str):
        try:
            return [int(p) for p in ip_str.split(".")]
        except Exception:
            return [0, 0, 0, 0]

    for ip in sorted(discovered.keys(), key=ip_sort_key):
        mac = discovered[ip]["mac"]
        
        name = ""
        try:
            name = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

        role = ""
        if ip == gateway_ip:
            role = "[GATEWAY]"
        elif ip == local_ip:
            role = "[THIS PC]"

        info = f"{role} {name}".strip() if role or name else "Connected Device"

        devices.append({"index": index, "ip": ip, "mac": mac, "name": name, "role": role})
        print(f"{index:<3} {ip:<16} {mac:<19} {info}")
        index += 1

    print("-" * 65)
    print(f"[+] Found {len(devices)} device(s).\n")
    return devices


if __name__ == "__main__":
    if len(sys.argv) > 1:
        scan_network(custom_subnet=sys.argv[1])
    else:
        scan_network()
