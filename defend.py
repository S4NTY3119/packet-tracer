"""
███████╗       ██╗██╗ ███╗   ██╗ ████████╗ ██╗   ██╗
██╔════╝     ██╔╝ ██║ ████╗  ██║ ╚══██╔══╝ ╚██╗ ██╔╝
███████╗   ██╔╝   ██║ ██╔██╗ ██║    ██║     ╚████╔╝ 
╚════██║  ██████████║ ██║╚██╗██║    ██║      ╚██╔╝  
███████║  ╚═══════██║ ██║ ╚████║    ██║       ██║   
╚══════╝          ╚═╝ ╚═╝  ╚═══╝    ╚═╝       ╚═╝
arp watchdog, nobody spoofin you today.
"""
import sys
import socket
import platform
import subprocess
import re
import uuid
from datetime import datetime

try:
    from scapy.all import conf, Ether, ARP, srp, sniff, get_if_hwaddr
    SCAPY_AVAILABLE = True
except ImportError:
    conf = None
    Ether = None
    ARP = None
    srp = None
    sniff = None
    get_if_hwaddr = None
    SCAPY_AVAILABLE = False


def get_local_ip():
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
        mac_hex = "{:012x}".format(uuid.getnode())
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
            output = subprocess.check_output("route print 0.0.0.0", shell=True).decode("utf-8", errors="ignore")
            for line in output.splitlines():
                if "0.0.0.0" in line:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                        return parts[2]
        except Exception:
            pass
    try:
        output = subprocess.check_output("ip route show default", shell=True).decode("utf-8", errors="ignore")
        match = re.search(r"default via ([\d\.]+)", output)
        if match:
            return match.group(1)
    except Exception:
        pass
    local_ip = get_local_ip()
    if local_ip != "127.0.0.1":
        parts = local_ip.split(".")
        return "{}.{}.{}.1".format(parts[0], parts[1], parts[2])
    return "192.168.1.1"


def resolve_mac(ip, timeout=2.0, retries=2):
    if not ip:
        return None
    if srp and Ether and ARP:
        try:
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
            ans, _ = srp(pkt, timeout=timeout, retry=retries, verbose=0)
            if ans:
                for _, rcv in ans:
                    if rcv.hwsrc:
                        return rcv.hwsrc.lower()
        except Exception:
            pass
    return None


def start_watchdog(gateway_ip=None):
    if not SCAPY_AVAILABLE:
        print("[!] Scapy not found. Install with: pip install scapy")
        return

    if not gateway_ip:
        auto_gw = get_default_gateway()
        inp = input("[?] Gateway IP [Enter for {}]: ".format(auto_gw)).strip()
        gateway_ip = inp if inp else auto_gw

    print("\n[*] ARP Watchdog running. Gateway: {}".format(gateway_ip))

    gateway_real_mac = resolve_mac(gateway_ip)
    if gateway_real_mac:
        print("[+] Gateway MAC: {}".format(gateway_real_mac))
    else:
        print("[!] Could not resolve gateway MAC - spoofing detection may be limited.")

    print("[*] Monitoring ARP replies (Ctrl+C to stop)...\n")

    def process_arp(packet):
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc.lower()
            timestamp = datetime.now().strftime("%H:%M:%S")
            if src_ip == gateway_ip:
                if gateway_real_mac and src_mac != gateway_real_mac.lower():
                    print("\n[{}] [ALERT] ARP Poisoning Detected! Gateway {} spoofed by {} (Legit: {})\n".format(
                        timestamp, gateway_ip, src_mac, gateway_real_mac))
                else:
                    print("[{}] Valid ARP reply from {} ({})".format(timestamp, gateway_ip, src_mac))

    try:
        sniff(filter="arp", prn=process_arp, store=False)
    except KeyboardInterrupt:
        print("\n[*] Watchdog stopped.\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] in ["--help", "-h"]:
        print("Usage: python defend.py [gateway_ip]")
    else:
        gw = sys.argv[1] if len(sys.argv) > 1 else None
        start_watchdog(gateway_ip=gw)
