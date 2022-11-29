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


import math
import os
import random
import re
import sys

from packet_analyser_p1 import * 
from packet_analyser_p2 import * 
from packet_analyser_p3 import *
from packet_analyser_p4 import *
from packet_analyser_p5 import *
from packet_analyser_p6 import *
from packet_analyser_p7 import *


 
#
# Please Paste all Fuctions from Part 1,2,3,4,5,6 & 7
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
 
 
# Complete the functions below.
 
#
 
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
# Complete the functions below.
#
 
def calScore(pkt):
    score = 0
    if pkt in flowAverage(packet_List):
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
    return [packet[0] for packet in ScoreList[1] if packet[1] > 5.00]
 
 
def getRegulPkts(ScoreList):
    return [packet[0] for packet in ScoreList[1] if packet[1] <= 5.00]
 
def isScore(ScoreList):
    return ScoreList[0] == 'SCORE' and type(ScoreList) == list and len(ScoreList) == 2
 
def isEmptyScore(ScoreList):
    return ScoreList[1] == [] and isScore(ScoreList)
# Complete the functions below.
#
 
def makePacketQueue():
    return ('PQ', [])
 
def contentsQ(q):
    return q[1]
 
def frontPacketQ(q):
    return contentsQ(q)[0]
 
def addToPacketQ(pkt,q):
    return contentsQ(q).insert(get_pos(pkt,contentsQ(q)), pkt)
 
def get_pos(pkt,lst):
    if (lst == []):
        return 0
    elif getSqn(pkt) < getSqn(lst[0]):
        return 0 + get_pos(pkt,[])
    else:
        return 1 + get_pos(pkt,lst[1:])
 
def removeFromPacketQ(q):
    contentsQ(q).pop(0)
 
def isPacketQ(q):
    return type(q) == tuple and q[0] == 'PQ' and type(contentsQ(q)) == list and len(q) == 2 
 
def isEmptPacketQ(q):
    return contentsQ(q) == [] and isPacketQ(q)
# Complete the functions below.
#
 
def makePacketStack():
    return ('PS', [])
 
def contentsStack(stk):
    return stk[1]
 
def topProjectStack (stk):
    return contentsStack(stk)[-1]
 
def pushProjectStack(pkt,stk):
    contentsStack(stk).append(pkt)
 
def popPickupStack(stk):
    contentsStack(stk).pop()
 
def isPKstack(stk):
    return type(stk) == tuple and stk[0] == 'PS' and type(contentsStack(stk)) == list and len(stk) == 2
 
def isEmptyPKStack(stk):
    return contentsStack(stk) == []
 
def sortPackets(scoreList,stack,queue):
    for packet in scoreList[1]:
        if packet[1] <= 5.00:
            addToPacketQ(packet[0],queue)
        else:
            pushProjectStack(packet[0],stack)
# Complete the function below.
#
 
def makePktLst(packet_List):
    q = makePacketQueue()
    for x in packet_List:
        contentsQ(q).append(makePacket(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]))
    return contentsQ(q)
 
 
def analysePackets(packet_List):
    stk = makePacketStack()
    q1 = makePacketQueue()
    q2 = makePacketQueue()
    sortPackets(makeScore(packet_List), stk, q1)
    for x in contentsQ(q1):
        addToPacketQ(x,q2)
    return q2
 
 
if __name__ == '__main__':
    fptr = open(os.environ['OUTPUT_PATH'], 'w')
 
    first_multiple_input = input().rstrip().split()
 
    srcIP = str(first_multiple_input[0])
    dstIP = str(first_multiple_input[1])
    length = int(first_multiple_input[2])
    prt = str(first_multiple_input[3])
    sp = int(first_multiple_input[4])
    dp = int(first_multiple_input[5])
    sqn = int(first_multiple_input[6])
    pld = int(first_multiple_input[7])
 
    ProtocolList = ["HTTPS","SMTP","UDP","TCP","DHCP","IRC"]
    IpBlackList = ["213.217.236.184","444.221.232.94","149.88.83.47","223.70.250.146","169.51.6.136","229.223.169.245"]
 
    packet_List = [(srcIP, dstIP, length, prt, sp, dp, sqn, pld),\
              ("111.202.230.44","62.82.29.190",31,"HTTP",80,20,1562436,38),\
              ("222.57.155.164","50.168.160.19",22,"UDP",90,5431,1662435,82),\
              ("333.230.18.207","213.217.236.184",56,"IRC",501,5643,1762434,318),\
              ("444.221.232.94","50.168.160.19",1003,"TCP",4657,4875,1962433,428),\
              ("555.221.232.94","50.168.160.19",236,"TCP",7753,5724,2062432,48)]
    packet_List = makePktLst(packet_List)
 
    fptr.write('Forward Packets => ' + str(analysePackets(packet_List)) + '\n')
 
    fptr.close()
