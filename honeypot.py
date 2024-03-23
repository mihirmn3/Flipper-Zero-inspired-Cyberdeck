from scapy.all import *
from connection_final import Connection
import random
from multiprocessing import Process

# Wireshark Filter: 
# wlan.addr_resolved==f2:65:ae:4b:9d:c8 && (wlan.fc.type_subtype== 0 || wlan.fc.type_subtype == 1 || wlan.fc.type_subtype == 11 || wlan.fc.type_subtype == 12)

interface = 'wlo1mon'
bssid = 'f2:65:ae:4b:9d:c8'
ssid = 'Zuraemon'
channel = chr(6)
broadcast_mac = 'ff:ff:ff:ff:ff:ff'

def generate_random_mac():
    """
    Generate a random MAC address string without any byte being '00' or 'FF'.

    Returns:
        str: Random MAC address string.
    """
    while True:
        # Generate 6 random hexadecimal digits
        hex_digits = [random.choice('123456789ABCDEF') for _ in range(12)]

        # For unicast address
        hex_digits[1] = random.choice('2468ACE')

        # Format the MAC address with colons
        mac_address = ':'.join([''.join(hex_digits[i:i+2]) for i in range(0, 12, 2)])
        
        # Check if the MAC address meets the condition
        if '00' not in mac_address and 'FF' not in mac_address:
            return mac_address.lower()

def connect_sta():
    
    connected = False
    sta_mac = ''

    while connected == False:
        sta_mac = generate_random_mac()
        ping_frame = RadioTap()\
                    /Dot11(type=0, subtype=4, addr1=broadcast_mac, addr2=sta_mac, addr3=broadcast_mac)\
                    /Dot11ProbeReq()\
                    /Dot11Elt(ID='SSID', info=ssid)\
                    /Dot11Elt(ID='Rates', info='\x82\x84\x8b\x96\x0c\x12\x18\x24')\
                    /Dot11Elt(ID='ESRates', info='\x30\x48\x60\x6c')\
                    /Dot11Elt(ID='DSset', info=channel)
        sendp(ping_frame, iface=interface, count=10, verbose=False)
        connection = Connection(sta_mac, bssid, ssid)
        connected = connection.make_connection(True)
    
    print("{} connected to {}".format(sta_mac, ssid))
    return connection

honeypot_size = 1
mac_list = []
unauthenticated_mac = []
authenticated_mac = []
associated_mac = []

print("\nCreating honeypot of 10 spoof MAC addresses connected to AP\n")

for _ in range(honeypot_size):
        connection = connect_sta()
        mac_list.append(connection)

print("\nHoneypot successfully created.")

# Using one thread for every MAC address
# print("Periodically sending probe request to the AP")
# ping_frame = RadioTap()\
#             /Dot11(type=0, subtype=4, addr1=broadcast_mac, addr2=mac_list[0].sta_mac, addr3=broadcast_mac)\
#             /Dot11ProbeReq()\
#             /Dot11Elt(ID='SSID', info=ssid)\
#             /Dot11Elt(ID='Rates', info='\x82\x84\x8b\x96\x0c\x12\x18\x24')\
#             /Dot11Elt(ID='ESRates', info='\x30\x48\x60\x6c')\
#             /Dot11Elt(ID='DSset', info=channel)
# time.sleep(2)
# sendp(ping_frame, iface=interface, count=100, verbose=False)

# Using one thread for every MAC address
print("Scanning for Deauth packets destined for any of the spoof MAC addresses...")
mac_list[0].mon_ifc.search_deauth()