import subprocess
import re
import serial
import time
import sys

def get_wifi_config():
    try:
        out = subprocess.check_output('netsh wlan show networks', shell=True).decode(errors='ignore')
        ssids = []
        for line in out.split('\n'):
            line = line.strip()
            if line.startswith('SSID') and ':' in line:
                ssid = line.split(':', 1)[1].strip()
                if ssid and ssid not in ssids:
                    ssids.append(ssid)
        
        if not ssids:
            print("No networks found.")
            return input("Enter SSID manually: ").strip(), input("Enter password: ").strip()
            
        print("\nAvailable WiFi Networks:")
        for i, s in enumerate(ssids):
            print(f" {i+1}. {s}")
            
        choice = input("\nSelect a network (number): ").strip()
        try:
            ssid = ssids[int(choice)-1]
        except:
            ssid = choice
            
        import getpass
        password = getpass.getpass(f"Enter password for {ssid}: ")
        if password.endswith("\r"): password = password[:-1]
        if password.endswith("\n"): password = password[:-1]
        
        return ssid, password
    except Exception as e:
        print(f"Error getting WiFi networks: {e}")
        return input("Enter SSID: ").strip(), input("Enter password: ")

def get_gateway_info():
    try:
        out = subprocess.check_output("ipconfig", shell=True).decode(errors='ignore')
        gw_ip = None
        for line in out.split('\n'):
            if "Default Gateway" in line and ":" in line:
                val = line.split(":")[-1].strip()
                if val:
                    gw_ip = val
                    break
        if not gw_ip: return "10.56.106.125", "f6:52:df:48:d1:fc"
        
        arp_out = subprocess.check_output("arp -a", shell=True).decode(errors='ignore')
        for line in arp_out.split('\n'):
            if gw_ip in line:
                parts = line.split()
                if len(parts) >= 2 and '-' in parts[1]:
                    return gw_ip, parts[1].replace('-', ':').lower()
        return gw_ip, "f6:52:df:48:d1:fc"
    except:
        return "10.56.106.125", "f6:52:df:48:d1:fc"

def main():
    print("Available ports:")
    print(" - COM5: USB-SERIAL CH340 (COM5)")
    port = input("Enter the COM port: ").strip()
    
    try:
        ser = serial.Serial(port, 115200, timeout=1)
        time.sleep(2)
        print(f"------MITM Defender Admin Server listening on {port}------")
    except Exception as e:
        print(f"Error opening serial port: {e}")
        return

    ssid, password = get_wifi_config()
    gw_ip, gw_mac = get_gateway_info()
    
    cfg_str = f"CFG|{gw_ip}|{gw_mac}|{ssid}|{password}\n"
    
    print("Sent config to ESP32: ")
    print(f"- IP={gw_ip}, MAC={gw_mac}, SSID={ssid}, PASS={{********}}")
    
    ser.write(cfg_str.encode('utf-8'))
    
    import threading
    def read_serial():
        detected_mac = None
        while True:
            try:
                if ser.in_waiting:
                    line = ser.readline().decode(errors='ignore').strip()
                    if line:
                        # Silently drop the frame type error spam
                        if "wifi:unsupport frame type" in line:
                            continue
                            
                        if line == "wrong pass":
                            print(line)
                        else:
                            print(f"[ESP32] {line}")

                        # Extract spoofed router MAC
                        mac_match = re.search(r"ROUTER MAC has been spoofed by\s+([0-9A-Fa-f:]+)", line, re.IGNORECASE)
                        if mac_match:
                            detected_mac = mac_match.group(1).replace('-', ':').lower()

                        # Silently disconnect in background if it's this PC's MAC (no terminal output)
                        if "initiating countermeasures" in line.lower():
                            if detected_mac == "{your_mac}":
                                try:
                                    subprocess.run(
                                        ["powershell", "-Command", "netsh wlan disconnect"],
                                        stdout=subprocess.DEVNULL,
                                        stderr=subprocess.DEVNULL,
                                        check=False
                                    )
                                except Exception:
                                    pass
                            detected_mac = None
            except: break
    
    t = threading.Thread(target=read_serial, daemon=True)
    t.start()

    try:
        while True:
            user_input = input()
            if user_input.strip().lower() == 't':
                ser.write(b"T\n")
    except KeyboardInterrupt:
        print("\n[*] Server shutting down.")
        ser.close()

if __name__ == "__main__":
    main()
