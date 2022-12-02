#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# All Rights Reserved - No usage allowed
# File              : packet_analyser_p4.py
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
from packet_analyser_p3 import *





def makePacket(srcIP, dstIP, length, prt, sp, dp, sqn, pld):
    return ("PK", srcIP, dstIP, [length, prt, [sp, dp], sqn, pld])
 
def getPacketSrc(pkt):
    return pkt[1]
 
def getPacketDst(pkt):
    return pkt[2]
 
def getPacketDetails(pkt):
    return pkt[3]
 
def isPacket(pkt):
    return type(pkt) == tuple and pkt[0] == "PK" and len(pkt) == 4 and type(getPacketDetails(pkt)) == list
 
 
def isEmptyPkt(pkt):
    return isPacket(pkt) and getPacketDetails(pkt) == []
 
 
def getLength(pkt):
    return getPacketDetails(pkt)[0]
 
def getProtocol(pkt):
    return getPacketDetails(pkt)[1]
 
def getSrcPort(pkt):
    return getPacketDetails(pkt)[2][0]
 
def getDstPort(pkt):
    return getPacketDetails(pkt)[2][1]
 
def getSqn(pkt):
    return getPacketDetails(pkt)[3]
 
def getPayloadSize(pkt):
    return getPacketDetails(pkt)[4]
 
 
def flowAverage(pkt_list):
    sumPayload = 0
    avgPayload = 0
    for packet in pkt_list:
        sumPayload += getPayloadSize(packet)
    avgPayload = sumPayload / len(pkt_list)
    return [packet for packet in pkt_list if getPayloadSize(packet) > avgPayload ]
 
def suspPort(pkt):
    return getSrcPort(pkt) > 500 or getDstPort(pkt) > 500
 
def suspProto(pkt):
    return getProtocol(pkt) not in ProtocolList 
 
def ipBlacklist(pkt):
    return getPacketSrc(pkt) in IpBlackList
 
def calScore(pkt):
    score = 0
    if pkt in flowAverage(pkt_list):
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
 
def addPacket(ScoreList, pkt):
    ScoreList[1].append((pkt,calScore(pkt)))
 
def getSuspPkts(ScoreList):
    return list(filter(lambda x: x[0] > 5.00, ScoreList[1]))
 
 
def getRegulPkts(ScoreList):
    return list(filter(lambda x: x[0] <= 5.00, ScoreList[1]))
 
def isScore(ScoreList):
    return ScoreList[0] == 'SCORE' and type(ScoreList) == list and len(ScoreList) == 2
 
def isEmptyScore(ScoreList):
    return ScoreList[1] == [] and isScore(ScoreList)
 
