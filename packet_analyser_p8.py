#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# All Rights Reserved - No usage allowed
# File              : packet_analyser_p8.py
# Author            : Camarly Thomas 
# Author            : Michael Leighton

"""
Group Information: 
Camarly Thomas : 620158933 
Michael Leighton : 620146318
"""

# Date              : 25.11.2022
# Last Modified Date: 25.11.2022
# Last Modified By  : Camarly Thomas 

from packet_analyser_p1 import * 
from packet_analyser_p2 import * 
from packet_analyser_p3 import *
from packet_analyser_p4 import *
from packet_analyser_p5 import *
from packet_analyser_p6 import *
from packet_analyser_p7 import *


def analysePackets(packet_List):
    packets = []
    for packet in packet_List:
        packets.append(makePacket(packet[0],packet[1],packet[2],packet[3],packet[4],packet[5],packet[6],packet[7]))
    def calScore(pkt):
        score = 0
        if pkt in flowAverage(packets):
            score += 3.56
        if suspProto(pkt):
            score += 2.74
        if suspPort(pkt):
            score += 1.45
        if ipBlacklist(pkt):
            score += 10
        return score
    def makeScore(pkt_list):
        return ['SCORE', [(packet,calScore(packet)) for packet in pkt_list]]
    packet_Scores = makeScore(packets)
    stack = makePacketStack()
    queue = makePacketQueue()
    sortPackets(packet_Scores,stack,queue)
    return queue
