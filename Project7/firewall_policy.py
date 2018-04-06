#!/usr/bin/python
# CS 6250 Spring 2018 - Project 7 - SDN Firewall

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import packets
from pyretic.core import packet 

'''
=========================================================================
Firewall config keys:
=========================================================================
'rulenum'
'macaddr_src'
'macaddr_dst'
'ipaddr_src'
'ipaddr_dst'
'port_src'
'port_dst'
'protocol'
=========================================================================
MATCH keys:
=========================================================================
FIELD       TYPE                EXAMPLE
switch      int                 4

inport      int                 3

outport     int                 2

srcmac      EthAddr             EthAddr('00:00:00:00:00:01') 

dstmac      EthAddr             EthAddr('00:00:00:00:00:03') 

srcip       IPAddr or string    IPAddr('10.0.1.1'), '10.0.0.0/24' 

dstip       IPAddr or string    IPAddr('10.0.1.2'), '10.0.0.1/24'

tos         int                 0 

srcport     int                 80   (Requires the ethtype and protocol to be set)
dstport     int                 8080 
ethtype     int                 1

protocol    int                 17   (Requires the ethtype to be set)
vlan_id     int                 0 

vlan_pcp    int                 0 
============================================================================
'''

def make_firewall_policy(config):

    # You may place any user-defined functions in this space.

    # feel free to remove the following "print config" line once you no longer need it
    #print config # for demonstration purposes only, so you can see the format of the config

    rules = []

    for entry in config:

        # TODO - This is where you build your firewall rules...
        # Note that you will need to delete the first rule line below when you create your own
        # firewall rules.  Refer to the Pyretic github documentation for instructions on how to
        # format these commands.
        # Example (but incomplete)
        #rule = match(dstport=int(entry['port_dst']),ethtype=packet.IPV4, protocol=packet.TCP_PROTO)

        entryRules = []

        ruleNum = entry['rulenum']
        macaddr_src = entry['macaddr_src']
        macaddr_dst = entry['macaddr_dst']
        ipaddr_src = entry['ipaddr_src']
        ipaddr_dst = entry['ipaddr_dst']
        port_src = entry['port_src']
        port_dst = entry['port_dst']
        protocol = entry['protocol']

        print("Rule Number: " + str(ruleNum))
        print("    Mac Src: " + str(macaddr_src))
        print("    Mac Dst: " + str(macaddr_dst))
        print("     Ip Src: " + str(ipaddr_src))
        print("     Ip Dst: " + str(ipaddr_dst))
        print("    Prt Src: " + str(port_src))
        print("    Prt Dst: " + str(port_dst))
        print("      Proto: " + str(protocol))

        rule=None

        if len(macaddr_src) == 17:
            entryRules.append(match(srcmac=EthAddr(macaddr_src)))
        if len(macaddr_dst) == 17:
            entryRules.append(match(dstmac=EthAddr(macaddr_dst)))
        if ipaddr_src != "-" and len(ipaddr_src)>1:
            entryRules.append(match(srcip=IPAddr(ipaddr_src)))
        if ipaddr_dst != "-" and len(ipaddr_dst)>1:
            entryRules.append(match(dstip=IPAddr(ipaddr_dst)))
        if port_src != "-" and len(port_src)>0:
            entryRules.append(match(srcport=int(port_src)))
        if port_dst != "-" and len(port_dst)>0:
            entryRules.append(match(dstport=int(port_dst)))
        if protocol != "-":
            if protocol == 'T':
                entryRules.append(match(protocol=packet.TCP_PROTO))
            if protocol == 'U':
                entryRules.append(match(protocol=packet.UDP_PROTO))
            if protocol == 'B':
                entryRules.append(match(protocol=(packet.TCP_PROTO | packet.UDP_PROTO)))
        if len(entryRules)>0:
            rule = entryRules[0]
            for i in range(1,len(entryRules)):
                rule &= entryRules[i]
        
        if rule != None:
            rules.append(rule)

    allowed = ~(union(rules))

    return allowed
