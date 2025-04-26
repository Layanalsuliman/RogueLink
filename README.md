# RogueLink
RogueLink is a Python-based Evil Twin Attack tool for cybersecurity learning and awareness.
It automates network scanning, deauthentication attacks, Evil Twin creation with a captive portal, and handshake capturing for WPA/WPA2 cracking experiments.
The tool provides a user-friendly interactive menu and supports custom captive portals to simulate real-world phishing scenarios in a controlled environment.
# Features
1. Network Interface Management
•	Select Interface: Choose a wireless network interface from available devices.
•	Enable Monitor Mode: Switch the selected interface into monitor mode using airmon-ng.
•	Disable Monitor Mode: Revert the interface back to managed mode.
2. Target Exploration
•	Explore Targets: Scan for nearby wireless networks and capture detailed information about SSIDs, BSSIDs, and channels.
3. Deauthentication Attack
•	RogueLink offers four different deauthentication attack modes:
o	Manual Mode: Specify BSSID, victim MAC, and channel for targeted deauthentication.
o	Auto Mode: Deauthenticate victim MAC across channels 1–50 automatically.
o	Manual Broadcast Mode: Deauthenticate all clients (broadcast) on a specific channel.
o	Auto Broadcast Mode: Broadcast deauthentication across channels 1–50.
These options allow users to customize the aggressiveness and targeting of the attack based on their needs.
4. Evil Twin Attack
•	Launch Evil Twin: Create a fake access point with a captive portal to capture user credentials.
•	Upload Custom Captive Portal: Replace the default captive portal with a custom-designed HTML template.
5. Handshake Capture
•	Capture 4-Way Handshake: Perform deauthentication and capture WPA/WPA2 handshakes from target networks, enabling offline password cracking.
6. Report Generation
•	Generate Report: Automatically generate a detailed text report including:
o	Selected interfaces,
o	Target BSSID and channel,
o	SSID used for the Evil Twin,
o	Captured credentials (if any).
7. Combined Deauth + Evil Twin Attack
•	Deauth + Evil Twin Attack: Launch a deauthentication attack first, then immediately start the Evil Twin attack for maximum effectiveness.
8. WPA Handshake Cracking
•	Crack WPA Handshake:
o	Crack captured WPA/WPA2 handshakes using a custom wordlist.
o	Optionally generate a wordlist automatically from captured portal credentials.

# Project Structure 

RogueLink/
├── logs/           # Captured credentials and reports
├── Templates/      # Pre-built captive portal templates
├── www/            # Web server root for Evil Twin captive portals
├── RogueLink.py    # Main tool script
├── README.md       # Project documentation

# Requirements

•	Python 3.x 
•	aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng)
•	hostapd
•	dnsmasq
•	apache2
•	Linux distribution (e.g., Kali Linux) with wireless card supporting monitor mode

# Installation & Usage

# Clone the repository
git clone https://github.com/yourusername/RogueLink.git

# Navigate to the project directory
cd RogueLink

# Run the tool
sudo python3 RogueLink.py

# Disclaimer ⚠️
RogueLink is created strictly for educational purposes, cybersecurity awareness, and authorized penetration testing environments.
Unauthorized use against networks you don't own is illegal.






