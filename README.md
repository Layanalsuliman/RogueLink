
# RogueLink

RogueLink is a Python-based Evil Twin Attack tool for cybersecurity learning and awareness.
It automates network scanning, deauthentication attacks, Evil Twin creation with a captive portal, and handshake capturing for WPA/WPA2 cracking experiments.
The tool provides a user-friendly interactive menu and supports custom captive portals to simulate real-world phishing scenarios in a controlled environment.

## Features

1. **Select Network Interface**  
2. **Enable Monitor Mode**  
3. **Disable Monitor Mode**  
4. **Explore Targets**  
5. **Deauthentication Attack**  
   - Manual Mode (Targeted deauth)  
   - Auto Mode (Across channels 1–50)  
   - Manual Broadcast Mode  
   - Auto Broadcast Mode  
6. **Evil Twin Attack**  
7. **Upload Custom Captive Portal**  
8. **Capture 4-Way Handshake**  
9. **Generate Report**  
10. **Deauth + Evil Twin Attack**  
11. **Crack WPA Handshake**


# Project Structure 

```
RogueLink/
├── logs/           # Captured credentials and reports
├── Templates/      # Pre-built captive portal templates
├── www/            # Web server root for Evil Twin captive portals
├── RogueLink.py    # Main tool script
└── README.md       # Project documentation
```

# Requirements

## Requirements
```
- Python 3.x
- aircrack-ng suite (airmon-ng, airodump-ng, aireplay-ng)
- hostapd
- dnsmasq
- apache2
- Linux distribution (e.g., Kali Linux) with wireless card supporting monitor mode
```

# Installation & Usage

# Clone the repository
```
git clone https://github.com/layanalsuliman/RogueLink.git
```
# Navigate to the project directory
```
cd RogueLink
```
# Run the tool
```
sudo python3 RogueLink.py
```
# Disclaimer ⚠️

RogueLink is created strictly for educational purposes, cybersecurity awareness, and authorized penetration testing environments.
Unauthorized use against networks you don't own is illegal.






