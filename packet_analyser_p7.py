
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# All Rights Reserved - No usage allowed
# File              : packet_analyser_p7.py
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


def sortPackets(scoreList,stack,queue):
    for packet in scoreList[1]:
        if packet[1] <= 5.00:
            addToPacketQ(packet[0],queue)
        else:
            pushProjectStack(packet[0],stack)


