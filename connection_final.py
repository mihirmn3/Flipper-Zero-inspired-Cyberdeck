#!/usr/bin/env python
from scapy.all import *
from monitor_ifc import Monitor
from multiprocessing import Process
import os
import sys

interface = 'wlo1mon'
ALGO_OPEN_AUTH = 0  # open authentication mode
START_SEQNUM = 1  # sequence number
COUNT = 5

class Connection:
      def __init__(self, sta_mac, bssid, ssid):
            self.bssid = bssid
            self.sta_mac = sta_mac
            self.ssid = ssid
            self.mon_ifc = Monitor(interface, sta_mac.lower(), bssid.lower())
            self.auth = False
            self.assoc = False

      def send_ack(self):
            ack = RadioTap()\
                  /Dot11(type=1, subtype=13, addr1=self.bssid)\
                  /Dot11Ack()
            sendp(ack, iface=interface, count=1, verbose=False)
      
      def send_auth(self):
            #authentication
            frame1 = RadioTap()\
                  /Dot11(type=0, subtype=11, addr1=self.bssid, addr2=self.sta_mac, addr3=self.bssid)\
                  /Dot11Auth(algo=0, seqnum=START_SEQNUM)
            # jobs = []
            # jobs.append(Process(target=sendp(frame1, iface=interface, count=COUNT, verbose=False)))
            # jobs.append(Process(target=self.mon_ifc.search_auth()))

            # for job in jobs:
            #       job.start()
            # for job in jobs:
            #       job.join()
            sendp(frame1, iface=interface, count=COUNT, verbose=False)
            self.mon_ifc.search_auth()
            self.auth = self.mon_ifc.auth_found
            return self.auth

      def send_assoc(self):
            #association
            frame2 = RadioTap()\
                  /Dot11(type=0, subtype=0, addr1=self.bssid, addr2=self.sta_mac, addr3=self.bssid)\
                  /Dot11AssoReq()\
                  /Dot11Elt(ID='SSID', info=self.ssid)\
                  /Dot11Elt(ID='Rates', info='\x82\x84\x8b\x96\x0c\x12\x18\x24')\
                  /Dot11Elt(ID='ESRates', info='\x30\x48\x60\x6c')
            jobs = []
            # jobs.append(Process(target=sendp(frame2, iface=interface, count=COUNT+100, verbose=False)))
            # jobs.append(Process(target=self.mon_ifc.search_assoc_resp()))

            # for job in jobs:
            #       job.start()
            # for job in jobs:
            #       job.join()
            sendp(frame2, iface=interface, count=COUNT+200, verbose=False)
            self.mon_ifc.search_assoc_resp()
            self.assoc = self.mon_ifc.assoc_found
            return self.assoc

      def make_connection(self, hide_output=False):
            
            if hide_output:
                  text_trap = io.StringIO()
                  sys.stdout = text_trap

            print("Sending authentication request...")
            if self.send_auth():
                  print("STA successfully authenticated to AP.")
                  # time.sleep(0.1)
                  self.send_ack()

                  print("\nSending association request...")
                  if self.send_assoc():
                        print("STA successfully associated with AP.")
                        self.send_ack()
                  else:
                        print("STA failed to associate with AP.")
            else:
                  print("STA failed to authenticate with AP.")
            
            if hide_output:
                  sys.stdout = sys.__stdout__
            return self.assoc