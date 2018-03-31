#!/usr/bin/python
# CS 6250 Spring 2018 - Project 7 - SDN Firewall

from pyretic.lib.corelib import *
from pyretic.lib.std import *
from pyretic.lib.query import packets
from pyretic.core import packet 

def make_firewall_policy(config):

    # You may place any user-defined functions in this space.

    # feel free to remove the following "print config" line once you no longer need it
    print config # for demonstration purposes only, so you can see the format of the config

    rules = []

    for entry in config:

        # TODO - This is where you build your firewall rules...
        # Note that you will need to delete the first rule line below when you create your own
        # firewall rules.  Refer to the Pyretic github documentation for instructions on how to
        # format these commands.
        # Example (but incomplete)
        rule = match(dstport=int(entry['port_dst']),ethtype=packet.IPV4, protocol=packet.TCP_PROTO)

        rules.append(rule)
        pass


    allowed = ~(union(rules))

    return allowed
