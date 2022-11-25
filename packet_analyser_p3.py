#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# All Rights Reserved - No usage allowed
# File              : packet_analyser_p3.py
# Author            : Camarly Thomas 
# Author            : Michael Leighton

"""
Group Information: 
Member 1: 620158933 
Member 2: 620146318
"""

# Date              : 24.11.2022
# Last Modified Date: 24.11.2022
# Last Modified By  : Camarly Thomas 

from packet_analyser_p1 import * 
from packet_analyser_p2 import * 




def flowAverage(pkt_list):
    """This metric will accept a list of packets and gets the average payload size of all the packets. It will return a list of packets that are above the average of the list."""
    sumPayload = 0
    for packet in pkt_list:
        sumPayload += getPayloadSize(packet)
    avgPayload = sumPayload / len(pkt_list)
    return [packet for packet in pkt_list if getPayloadSize(packet) > avgPayload]


def suspPort(pkt):
    """This metric will flag any packets with a source or destination port number that exceeds 500."""
    return getSrcPort(pkt) > 500 or getDstPort(pkt) > 500


def suspProto(pkt):
    """Suspicious Protocols – There are particular protocols that may be marked as suspicious. These protocols may indicate nefarious activity. In our tool we will reference a list of regular protocol and if the protocol of a given packet is not a prat of that list then the pact will be marked as suspicious."""
    return getProtocol(pkt) in ProtocolList

    

def ipBlacklist(pkt):
    """IP Blacklist – Throughout the SSSGO there are known Ip address that are infamous for sending malicious software, spam attacks or even denial of series attacks. These packets should be discarded immediately. Write a function to check if the source IP address of a packet matches any of the IP addresses in the IP backlist."""
    return getPacketSrc(pkt) in IpBlackList or getPacketDst(pkt) in IpBlackList

