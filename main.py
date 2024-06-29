from scapy.all import *
import json

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
        crypto = stats.get('crypto')

        # Extra information: Attack Validation

        if "WPA/PSK" in crypto or "WPA2/PSK" in crypto:
        # All intel aquired

        # Save Intel
            data = {"ssid":ssid, "bssid":bssid, "channel":channel, "crypto":crypto}
            networks.append(data)

def write_networks():
    with open('wifi_networks.json', 'r') as f:
        f.write(json.dumps(networks))





if __name__ == '__main__':
    sniff(prn=WifiEnumeration, iface='wlan0', timeout=5)
    write_networks()
