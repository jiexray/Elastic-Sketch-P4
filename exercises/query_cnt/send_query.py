#!/usr/bin/env python

import argparse
import sys
import socket
import random
import struct

from scapy.all import sendp, send, hexdump, get_if_list, get_if_hwaddr
from scapy.all import Packet, IPOption
from scapy.all import Ether, IP, UDP
from scapy.all import IntField, FieldListField, FieldLenField, ShortField, PacketListField, LongField, ByteField
from scapy.layers.inet import _IPOption_HDR

from time import sleep

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print "Cannot find eth0 interface"
        exit(1)
    return iface

class SwitchTrace(Packet):
    fields_desc = [ IntField("swid", 0),
                  IntField("qdepth", 0)]
    def extract_padding(self, p):
                return "", p

class IPOption_QUERY(IPOption):
    name = "QUERY"
    option = 31
    fields_desc = [ _IPOption_HDR,
                    ShortField("count", 0),
                    ByteField("flow_proto", 0)]


def main():

    if len(sys.argv)<2:
        print 'pass 2 arguments: <source> <destination>'
        exit(1)

    src_addr = socket.gethostbyname(sys.argv[1])
    addr = socket.gethostbyname(sys.argv[2])
    iface = get_if()

    pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
        src=src_addr, dst=addr, proto=63, options = IPOption_QUERY(count=10, flow_proto=6))

 #   pkt = Ether(src=get_if_hwaddr(iface), dst="ff:ff:ff:ff:ff:ff") / IP(
 #       dst=addr, options = IPOption_MRI(count=2,
 #           swtraces=[SwitchTrace(swid=0,qdepth=0), SwitchTrace(swid=1,qdepth=0)])) / UDP(
 #           dport=4321, sport=1234) / sys.argv[2]
    pkt.show2()
    #hexdump(pkt)
    # try:
    #   for i in range(int(sys.argv[4])):
    #     sendp(pkt, iface=iface)
    #     sleep(1)
    # except KeyboardInterrupt:
    #     raise
    try:
        sendp(pkt, iface=iface)
    except KeyboardInterrupt:
        raise


if __name__ == '__main__':
    main()
