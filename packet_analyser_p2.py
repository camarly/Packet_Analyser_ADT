#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# All Rights Reserved - No usage allowed
# File              : packet_analyser_p2.py
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

from packet_analyser_p1.py import * 


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
