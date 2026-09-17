"""
███████╗       ██╗██╗ ███╗   ██╗ ████████╗ ██╗   ██╗
██╔════╝     ██╔╝ ██║ ████╗  ██║ ╚══██╔══╝ ╚██╗ ██╔╝
███████╗   ██╔╝   ██║ ██╔██╗ ██║    ██║     ╚████╔╝ 
╚════██║  ██████████║ ██║╚██╗██║    ██║      ╚██╔╝  
███████║  ╚═══════██║ ██║ ╚████║    ██║       ██║   
╚══════╝          ╚═╝ ╚═╝  ╚═══╝    ╚═╝       ╚═╝
sniffer shyt, don't get caught.
"""
import sys
import os
import socket
import threading
import re
import struct
from datetime import datetime

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


APP_MAP = {
    "youtube": "YouTube",
    "googlevideo": "YouTube Video",
    "ytimg": "YouTube",
    "instagram": "Instagram",
    "cdninstagram": "Instagram",
    "facebook": "Facebook",
    "fbcdn": "Facebook",
    "whatsapp": "WhatsApp",
    "spotify": "Spotify",
    "netflix": "Netflix",
    "discord": "Discord",
    "tiktok": "TikTok",
    "snapchat": "Snapchat",
    "amazon": "Amazon",
    "reddit": "Reddit",
    "twitter": "Twitter",
    "x.com": "Twitter",
    "wikipedia": "Wikipedia",
    "github": "GitHub",
    "google": "Google",
    "chatgpt": "ChatGPT",
    "openai": "OpenAI",
    "telegram": "Telegram",
    "geeksforgeeks": "GeeksForGeeks",
    "stackoverflow": "StackOverflow",
    "bing": "Bing",
    "truecaller": "Truecaller",
    "unity3d": "Unity Network",
    "duolingo": "Duolingo",
    "steampowered": "Steam",
    "steam": "Steam",
    "brave": "Brave Browser"
}

PUSH_SERVICES = {
    "mtalk.google.com": "Google FCM Push",
    "fcm.googleapis.com": "Google FCM",
    "notifications-pa.googleapis.com": "Google Push Sync",
    "push.apple.com": "Apple APNs Push",
    "courier.push.apple.com": "Apple APNs Push",
    "gcm-http.googleapis.com": "Google GCM Push",
    "wns.windows.com": "Windows Push"
}

IGNORED_PATTERNS = [
    r"\.arpa$", r"\.local$", r"\.lan$", r"\.home$", r"\.internal$",
    r"events\.data\.microsoft\.com", r"dcg\.microsoft\.com",
    r"connectivitycheck\.gstatic\.com", r"connectivitycheck\.android\.com",
    r"time\.android\.com", r"time\.google\.com",
    r"^[0-9\.]+$",
    r"digicert\.com",              # Certificate checks
    r"miui\.com",                  # Xiaomi background telemetry
    r"xiaomi\.com",                # Xiaomi background telemetry
    r"xiaomi\.net",                # Xiaomi background telemetry
    r"scorecardresearch\.com",     # Analytics
    r"doubleclick\.net",           # Google Ads
    r"googleadservices\.com",      # Google Ads
    r"jio\.com",                   # Carrier background sync
    r"rt\.zd",                     # Tracking/telemetry
    r"branch\.io",                 # App deep-link telemetry
    r"ekatox\.com",                # App telemetry
    r"godaddy\.com",               # Parked domains / cert checks
    r"pangle\.io",                 # TikTok / ByteDance Ad Network
    r"tiktokpangle\.us",           # TikTok Ad Network
    r"i18n-pglstatp\.com",         # ByteDance telemetry
    r"byteoversea\.com",           # ByteDance telemetry
    r"faceueditor\.com",           # ByteDance telemetry
    r"vungle\.com",                # Vungle Ads
    r"moloco\.com",                # Moloco Ads
    r"appsflyersdk\.com",          # AppsFlyer Analytics
    r"asus\.com"                   # Asus background checks
]

TARGET_IP = None
SEEN_DOMAINS = {}


def is_push_service(domain):
    d = domain.lower()
    for push_domain, service_name in PUSH_SERVICES.items():
        if push_domain in d:
            return service_name
    return None


def is_ignored(domain):
    d = domain.lower()
    for pattern in IGNORED_PATTERNS:
        if re.search(pattern, d):
            return True
    return False


def get_app_name(domain):
    d = domain.lower()
    for key, name in APP_MAP.items():
        if key in d:
            return name
    parts = d.split(".")
    if len(parts) >= 2:
        return parts[-2].capitalize()
    return "Website"


def extract_sni_domain(payload):
    """Robust binary parser for extracting SNI from TLS Client Hello packets."""
    try:
        # TLS Record Header (5 bytes): Content Type (1), Version (2), Length (2)
        if len(payload) < 5 or payload[0] != 0x16: # 0x16 == Handshake
            return None
        
        # Handshake Header (4 bytes): Type (1), Length (3)
        if len(payload) < 9 or payload[5] != 0x01: # 0x01 == Client Hello
            return None

        # Offset to the start of Client Hello payload
        offset = 9
        
        # Client Version (2 bytes)
        offset += 2
        # Random (32 bytes)
        offset += 32
        
        # Session ID Length (1 byte) + Session ID
        if offset >= len(payload): return None
        session_id_len = payload[offset]
        offset += 1 + session_id_len
        
        # Cipher Suites Length (2 bytes) + Cipher Suites
        if offset + 1 >= len(payload): return None
        cipher_suites_len = struct.unpack_from(">H", payload, offset)[0]
        offset += 2 + cipher_suites_len
        
        # Compression Methods Length (1 byte) + Compression Methods
        if offset >= len(payload): return None
        comp_methods_len = payload[offset]
        offset += 1 + comp_methods_len
        
        # Extensions Length (2 bytes)
        if offset + 1 >= len(payload): return None
        extensions_len = struct.unpack_from(">H", payload, offset)[0]
        offset += 2
        
        # Parse Extensions
        end_offset = offset + extensions_len
        while offset + 3 < min(end_offset, len(payload)):
            ext_type = struct.unpack_from(">H", payload, offset)[0]
            ext_len = struct.unpack_from(">H", payload, offset+2)[0]
            offset += 4
            
            # SNI Extension (Type 0x0000)
            if ext_type == 0:
                if offset + 1 >= len(payload): return None
                list_len = struct.unpack_from(">H", payload, offset)[0]
                sni_offset = offset + 2
                
                while sni_offset + 2 < offset + ext_len:
                    name_type = payload[sni_offset]
                    if name_type == 0: # Hostname
                        name_len = struct.unpack_from(">H", payload, sni_offset+1)[0]
                        sni_offset += 3
                        domain = payload[sni_offset:sni_offset+name_len].decode('ascii', errors='ignore')
                        return domain
                    break
            offset += ext_len
            
    except Exception:
        pass
    return None


def handle_detected_domain(domain, timestamp, client_ip):
    global SEEN_DOMAINS
    now = datetime.now().timestamp()
    key = f"{client_ip}:{domain}"
    if key in SEEN_DOMAINS and (now - SEEN_DOMAINS[key]) < 2:
        return
    SEEN_DOMAINS[key] = now

    # Check for silent drops first before processing
    if is_ignored(domain):
        return

    push = is_push_service(domain)
    if push:
        print(f"[{timestamp}] [{client_ip}] Push Notification: {push} ---> {domain}")
        return

    app = get_app_name(domain)
    print(f"[{timestamp}] [{client_ip}] Visiting: {app:<15} ---> https://{domain}")


def analyze_packet(packet):
    global TARGET_IP
    try:
        from scapy.all import IP, TCP, Raw, DNS, DNSQR
    except ImportError:
        return

    if not packet.haslayer(IP):
        return

    src = packet[IP].src
    dst = packet[IP].dst

    if TARGET_IP and (src != TARGET_IP and dst != TARGET_IP):
        return

    if TARGET_IP:
        client_ip = TARGET_IP
    else:
        if src.startswith("192.168.") or src.startswith("10.") or src.startswith("172."):
            client_ip = src
        elif dst.startswith("192.168.") or dst.startswith("10.") or dst.startswith("172."):
            client_ip = dst
        else:
            client_ip = src

    timestamp = datetime.now().strftime("%H:%M:%S")

    # 1. Capture DNS Plaintext queries
    if packet.haslayer(DNS) and packet[DNS].qr == 0:
        try:
            domain = packet[DNSQR].qname.decode("utf-8", errors="replace").rstrip(".")
            if domain:
                handle_detected_domain(domain, timestamp, client_ip)
                return
        except Exception:
            pass

    # 2. Capture TLS SNI Handshakes (YouTube, Instagram use HTTPS heavily)
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        dport = packet[TCP].dport
        sport = packet[TCP].sport
        if dport in [443, 5228, 5229, 5230] or sport in [443, 5228, 5229, 5230]:
            payload = bytes(packet[Raw].load)
            domain = extract_sni_domain(payload)
            if domain:
                handle_detected_domain(domain, timestamp, client_ip)
                return

    # 3. Capture HTTP Host Headers
    if packet.haslayer(TCP) and packet.haslayer(Raw):
        if packet[TCP].dport == 80 or packet[TCP].sport == 80:
            try:
                data = packet[Raw].load.decode("utf-8", errors="replace")
                if data.startswith("GET") or data.startswith("POST"):
                    for line in data.split("\r\n"):
                        if line.lower().startswith("host:"):
                            host = line.split(":", 1)[1].strip()
                            if host:
                                handle_detected_domain(host, timestamp, client_ip)
                            break
            except Exception:
                pass


def start_sniffer(target_ip=None):
    global TARGET_IP
    auto_my_ip = get_local_ip()

    print(f"\n[*] Sniffer Host IP: {auto_my_ip}")

    if target_ip is None:
        choice = input("[?] Target IP to filter [Enter for all]: ").strip()
        TARGET_IP = choice if choice else None
    elif target_ip in ["all", "--all"]:
        TARGET_IP = None
    else:
        TARGET_IP = target_ip

    target_name = f"IP {TARGET_IP}" if TARGET_IP else "All Devices"
    print(f"[*] Monitoring: {target_name} (Ctrl+C to stop)\n")

    try:
        from scapy.all import sniff
        sniff(prn=analyze_packet, store=False, promisc=True)
    except KeyboardInterrupt:
        print("\n[*] Sniffer stopped.\n")


def start_proxy(listen_ip="0.0.0.0", listen_port=8080, log_file="proxy_traffic.log"):
    local_ip = get_local_ip()

    def handle_client(client_socket, addr):
        request = client_socket.recv(65535)
        if not request:
            client_socket.close()
            return

        try:
            first_line = request.split(b"\r\n")[0].decode('utf-8', errors='replace')
            method, url, _ = first_line.split(" ")
            if url.startswith("http://"):
                url = url[7:]
            host_port = url.split("/")[0]
            if ":" in host_port:
                host, port = host_port.split(":")
                port = int(port)
            else:
                host = host_port
                port = 80
            path = "/" + "/".join(url.split("/")[1:])
        except Exception:
            client_socket.close()
            return

        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"[{timestamp}] [{addr[0]}] Proxy: http://{host}:{port}{path}")

        with open(log_file, "a", encoding="utf-8") as f:
            f.write(f"[{timestamp}] {addr[0]} -> http://{host}:{port}{path}\n")

        try:
            remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            remote.settimeout(10)
            remote.connect((host, port))
            remote.send(request)

            while True:
                chunk = remote.recv(65535)
                if not chunk:
                    break
                try:
                    client_socket.send(chunk)
                except Exception:
                    break
            remote.close()
        except Exception:
            try:
                client_socket.send(b"HTTP/1.1 502 Bad Gateway\r\n\r\nProxy Error")
            except Exception:
                pass

        client_socket.close()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((listen_ip, listen_port))
    server.listen(50)

    print(f"\n[*] Proxy running on: {listen_ip}:{listen_port}")
    print(f"[*] Target device proxy settings -> {local_ip}:{listen_port}")
    print(f"[*] Logging requests to: {log_file} (Ctrl+C to stop)\n")

    try:
        while True:
            client, addr = server.accept()
            t = threading.Thread(target=handle_client, args=(client, addr))
            t.daemon = True
            t.start()
    except KeyboardInterrupt:
        print("\n[*] Proxy stopped.\n")
        server.close()


if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1].strip()
        if arg in ["--proxy", "-p"]:
            port = int(sys.argv[2]) if len(sys.argv) > 2 and sys.argv[2].isdigit() else 8080
            start_proxy(listen_port=port)
        elif arg in ["--all", "-a"]:
            start_sniffer(target_ip="all")
        elif arg in ["--help", "-h"]:
            print("Usage: python sniffer.py [target_ip] | --all | --proxy [port]")
        else:
            start_sniffer(target_ip=arg)
    else:
        start_sniffer()