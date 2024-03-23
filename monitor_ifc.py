from scapy.all import *
 
class Monitor:
    def __init__(self, mon_ifc, sta_mac, bssid):
        """
 
        :param mon_ifc: WLAN interface to use as a monitor
        :param channel: Channel to operate on
        :param sta_mac: MAC address of the STA
        :param bssid: BSSID of the AP to attack
        """
        self.mon_ifc = mon_ifc
        self.sta_mac = sta_mac
        self.bssid = bssid
        self.auth_found = False
        self.assoc_found = False
        self.deauth_found = False
 
    def check_auth(self, packet):
        """
        Try to find the Authentication from the AP
 
        :param packet: sniffed packet to check for matching authentication
        """
        seen_receiver = packet[Dot11].addr1
        seen_sender = packet[Dot11].addr2
        seen_bssid = packet[Dot11].addr3
 
        # print(seen_receiver, self.sta_mac)
        # print(seen_sender, self.bssid)
        # print(seen_bssid, self.bssid, end="\n\n")

        if self.bssid == seen_bssid and \
            self.bssid == seen_sender and \
                self.sta_mac == seen_receiver:
            self.auth_found = True
            print("Detected Authentication from Source {0}".format(
                seen_bssid))
        return self.auth_found

    def check_assoc(self, packet):
        """
        Try to find the Association Response from the AP
 
        :param packet: sniffed packet to check for matching association
        """
        seen_receiver = packet[Dot11].addr1
        seen_sender = packet[Dot11].addr2
        seen_bssid = packet[Dot11].addr3
 
        if self.bssid == seen_bssid and \
            self.bssid == seen_sender and \
                self.sta_mac == seen_receiver:
            self.assoc_found = True
            print("Detected Association Response from Source {0}".format(
                seen_bssid))
        return self.assoc_found
 
    def check_deauth(self, packet):
        """
        Try to find the Deauthentication from the AP
 
        :param packet: sniffed packet to check for matching deauthentication
        """
        seen_receiver = packet[Dot11].addr1
        seen_sender = packet[Dot11].addr2
        seen_bssid = packet[Dot11].addr3
        
        if seen_receiver == "ff:ff:ff:ff:ff:ff":
            seen_receiver = self.sta_mac

        if self.bssid == seen_bssid and \
            self.bssid == seen_sender and \
                self.sta_mac == seen_receiver:
            self.deauth_found = True
            print("Detected Deauthentication of {0} from Source {1}".format(self.sta_mac,
                seen_bssid))
        return self.deauth_found

    def search_auth(self):
        print("\nScanning max 5 seconds for Authentication "
              "from BSSID {0}".format(self.bssid))
        sniff(iface=self.mon_ifc, lfilter=lambda x: x.haslayer(Dot11Auth),
              stop_filter=self.check_auth,
              timeout=5)
        # return self.auth_found
 
    def search_assoc_resp(self):
        print("\nScanning max 5 seconds for Association Response "
              "from BSSID {0}".format(self.bssid))
        sniff(iface=self.mon_ifc, lfilter=lambda x: x.haslayer(Dot11AssoResp),
              stop_filter=self.check_assoc,
              timeout=5)
        # return self.assoc_found
    
    def search_deauth(self):
        print("\nScanning max 1 minute for Deauthentication "
              "from BSSID {0}".format(self.bssid))
        sniff(iface=self.mon_ifc, lfilter=lambda x: x.haslayer(Dot11Deauth),
              stop_filter=self.check_deauth,
              timeout=60)
        return self.deauth_found