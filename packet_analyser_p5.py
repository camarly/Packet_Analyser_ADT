#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# All Rights Reserved - No usage allowed
# File              : packet_analyser_p5.py
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


def makePacketQueue():
    return ("PQ", [])


def contentsQ(q):
    return q[1]


def frontPacketQ(q):
    return contentsQ[0]


def addToPacketQ(pkt,q):
    contentsQ(q).insert(get_pos(pkt, contentsQ(q)),pkt)


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
    return type(q) == tuple and q[0] == "PQ" and type(contentsQ(q)) == list and len(q) == 2
    

def isEmptPacketQ(q):
    return contentsQ(q) == [] and isPacketQ(q)
    
    

