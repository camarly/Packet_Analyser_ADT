
#!/usr/bin/env python3
#!/bin/python3

# -*- coding: utf-8 -*-
# File              : packet_analyser_p9.py
# Author            : Camarly Thomas 
# Author            : Michael Leighton
# Date              : 26.11.2022
# Last Modified Date: 26.11.2022
# Last Modified By  : Camarly Thomas

"""
Group Information: 
Camarly Thomas : 620158933 
Michael Leighton : 620146318
"""

 
import math
import os
import random
import re
import sys
 

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
 

 
def flowAverage(pkt_list):
    """This metric will accept a list of packets and gets the average payload size of all the packets. It will return a list of packets that are above the average of the list."""
    sumPayload = 0
    avgPayload = 0
    for packet in pkt_list:
        sumPayload += getPayloadSize(packet)
    avgPayload = sumPayload / len(pkt_list)
    return [packet for packet in pkt_list if getPayloadSize(packet) > avgPayload ]
 
def suspPort(pkt):
    """This metric will flag any packets with a source or destination port number that exceeds 500."""
    return getSrcPort(pkt) > 500 or getDstPort(pkt) > 500
 
def suspProto(pkt):
    """This function will reference a list of regular protocols and if the protocol of a given packet is not a part of that list then the packet will be marked as suspicious."""
    return getProtocol(pkt) not in ProtocolList 
 
 
def ipBlacklist(pkt):
    """function to check if the source IP address of a packet matches any of the IP addresses in the IP backlist"""
    return getPacketSrc(pkt) in IpBlackList
# Complete the functions below.
#
 
def calScore(pkt):
    """Takes a List of Packets and returns a score list, where the first part of the list is a tag ‘SCORE."""
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
    """Takes a List of Packets and returns a score list, where the first part of the list is a tag ‘SCORE."""
    return ['SCORE', [(packet,calScore(packet)) for packet in pkt_list]]
 
 
def addPacket(ScoreList, pkt):
    """Takes a Score List and a Packet as input and adds the packet to the score list. this function calculates the packet score before adding it to the list."""
    ScoreList[1].append((pkt,calScore(pkt)))
 
def getSuspPkts(ScoreList):
    """Takes a Score as an input and returns a list of all suspicious packets."""
    return list(filter(lambda x: x[0] > 5.00, ScoreList[1]))
 
def getRegulPkts(ScoreList):
    """Takes a Score as an input and returns a list of all regular packets."""
    return list(filter(lambda x: x[0] <= 5.00, ScoreList[1]))
 
def isScore(ScoreList):
    """Checks to see if a given list, is a valid Score."""
    return ScoreList[0] == 'SCORE' and type(ScoreList) == list and len(ScoreList) == 2
 
def isEmptyScore(ScoreList):
    """Checks to see if a given Score list is empty."""
    return ScoreList[1] == [] and isScore(ScoreList)

 
def makePacketQueue():
    """Returns an empty Packet Queue as a tuple, where the first part of the tuple is a tag ‘PQ’ and the second part of the tuple is an empty list."""
    return ('PQ', [])
 
def contentsQ(q):
    """Takes a Packet Queue as input and returns the list of Packets in the Packet Queue."""
    return q[1]
 
def frontPacketQ(q):
    """Takes a Packet Queue as an input and returns the element in the front of the list."""
    return contentsQ(q)[0]
 
def addToPacketQ(pkt,q):
    """Takes a Packet and a Packet Queue as input and adds the given packet to the appropriate position in the queue."""
    return contentsQ(q).insert(get_pos(pkt,contentsQ(q)), pkt)
 
def get_pos(pkt,lst):
    if (lst == []):
        return 0
    elif getSqn(pkt) < getSqn(lst[0]):
        return 0 + get_pos(pkt,[])
    else:
        return 1 + get_pos(pkt,lst[1:])
 
def removeFromPacketQ(q):
    """Takes a Packet Queue as input and removes the front element from the Queue."""
    contentsQ(q).pop(0)
 
def isPacketQ(q):
    """Checks to see if a given Queue is a valid Packet Queue."""
    return type(q) == tuple and q[0] == 'PQ' and type(contentsQ(q)) == list and len(q) == 2 
 
def isEmptPacketQ(q):
    """Checks to see if a given Packet Queue is empty."""
    return contentsQ(q) == [] and isPacketQ(q)

 
def makePacketStack():
    """Returns an empty Packet Stack as a tuple, where the first part of the tuple is a tag ‘PS’ and the second part of the tuple is an empty list."""
    return ('PS', [])
 
def contentsStack(stk):
    """Takes a Packet Stack as input and returns the list of Packets in the Stack."""
    return stk[1]
 
def topProjectStack (stk):
    """Takes a Packet Stack as an input and returns the element on the top of the stack."""
    return contentsStack(stk)[-1]
 
def pushProjectStack(pkt,stk):
    """Takes a Packet and a Packet Stack as input and adds the packet to the top of the stack."""
    contentsStack(stk).append(pkt)
 
def popPickupStack(stk):
    """Takes a Packet Stack as input and removes the top element from the stack."""
    contentsStack(stk).pop()
 
def isPKstack(stk):
    """Checks to see if a given Stack is indeed a valid Packet Stack."""
    return type(stk) == tuple and stk[0] == 'PS' and type(contentsStack(stk)) == list and len(stk) == 2
 
def isEmptyPKStack(stk):
    """Checks to see if a given Packet Stack is empty."""
    return contentsStack(stk) == []
 
def sortPackets(scoreList,stack,queue):
    for packet in scoreList[1]:
        if packet[1] <= 5.00:
            addToPacketQ(packet[0],queue)
        else:
            pushProjectStack(packet[0],stack)
 
 
#generates packet list 
def genPacketList(packet_List):
    """Takes a list of packet details and returns a list of packets made from those details"""
    q = makePacketQueue()
    for x in packet_List:
        contentsQ(q).append(makePacket(x[0], x[1], x[2], x[3], x[4], x[5], x[6], x[7]))
    return contentsQ(q)
 
 
def analysePackets(packet_List):
    """function takes in list of packets in non-ADT form and makes packets, scores each packet by analysing packets registering suspicion score. Separates packets based on score to eitehr the priority queue or stack. The Queue of packets to be forwarded are returned."""
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
 
    packet_List = [(srcIP, dstIP, length, prt, sp, dp, sqn, pld),\
                   ("111.202.230.44","62.82.29.190",31,"HTTP",80,20,1562436,338),\
                   ("222.57.155.164","50.168.160.19",22,"UDP",790,5431,1662435,812),\
                   ("333.230.18.207","213.217.236.184",56,"IMCP",501,5643,1762434,3138),\
                   ("444.221.232.94","50.168.160.19",1003,"TCP",4657,4875,1962433,428),\
                   ("555.221.232.94","50.168.160.19",236,"HTTP",7753,5724,2062432,48)]
    
    #needed for flowAverage calculation
    packet_List = genPacketList(packet_List)
    
    ProtocolList = ["HTTPS","SMTP","UDP","TCP","DHCP","IRC"]
    IpBlackList = []
 
    fptr.write('Forward Packets => ' + str(analysePackets(packet_List)) + '\n')
 
    fptr.close()
    