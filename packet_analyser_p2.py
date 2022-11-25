#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# All Rights Reserved - No usage allowed
# File              : packet_analyser_p1.py
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


def makePacket(srcIP, dstIP, length, prt, sp, dp, sqn, pld):
    """Takes Packet information and returns a Packet as a tuple, where the first part of the tuple is a tag ‘PK’."""
    return ("PK", srcIP, dstIP, [length, prt, [sp, dp], sqn, pld])
    
def getPacketSrc(pkt):
    """Takes a Packet as input and returns the source IP address of the Packet."""
    return pkt[1]
    
def getPacketDst(pkt):
    """Takes a Packet as input and returns the destination IP address of the Packet."""
    return pkt[2]
    
def getPacketDetails(pkt):
    """Takes a Packet as input and returns the list with the Packet details information."""
    return pkt[3]
    
def isPacket(pkt):
    """Checks to see if a given Packet, is a valid Packet."""
    return type(pkt) == tuple and pkt[0] == "PK" and len(pkt) == 4 and type(getPacketDetails(pkt)) == list


def isEmptyPkt(pkt):
    """Checks to see if a given Packet is empty."""
    return isPacket(pkt) and getPacketDetails(pkt) == []

def getLength(pkt):
    """Takes a Packet as input and returns the Length of the Packet in bytes."""
    return getPacketDetails(pkt)[0]
    

def getProtocol(pkt):
    """Takes a Packet as input and returns the Protocol of the Packet."""
    return getPacketDetails(pkt)[1]

def getSrcPort(pkt):
    """Takes a Packet as input and returns the Source port of the Packet."""
    return getPacketDetails(pkt)[2][0]

def getDstPort(pkt):
    """Takes a Packet as input and returns the Destination port of the Packet."""
    return getPacketDetails(pkt)[2][1]

def getSqn(pkt):
    """Takes a Packet as input and returns the Sequence number of the Packet."""
    return getPacketDetails(pkt)[3]

def getPayloadSize(pkt):
    """Takes a Packet as input and returns the Payload size of the Packet."""
    return getPacketDetails(pkt)[4]
