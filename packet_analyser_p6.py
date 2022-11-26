
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# All Rights Reserved - No usage allowed
# File              : packet_analyser_p6.py
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




def makePacketStack():
    return ("PS", [])
  

def contentsStack(stk):
    return stk[1]
  

def topProjectStack (stk):
    return contentsStack(stk)[-1]
  

def pushProjectStack(pkt,stk):
    contentsStack(stk).append(pkt)
    

def popPickupStack(stk):
    contentsStack(stk).pop()
  

def isPKstack(stk):
    return type(stk) == tuple and stk[0] == "PS" and type(contentsStack(stk)) == list and len(stk) == 2
  

def isEmptyPKStack(stk):
    return contentsStack(stk) == []
