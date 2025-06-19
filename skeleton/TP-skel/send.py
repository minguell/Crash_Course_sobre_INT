#!/usr/bin/env python3
import random
import socket
import sys

from scapy.all import IP, TCP, Ether, get_if_hwaddr, get_if_list, sendp
from INT_headers import INTParent, INTChild


def get_if():
    ifs = get_if_list()
    iface = None  # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


def main():

    if len(sys.argv) < 3:
        print('pass 2 arguments: <destination> "<message>"')
        exit(1)

    addr = socket.gethostbyname(sys.argv[1])
    message = sys.argv[2]
    iface = get_if()

    # Example INTParent and INTChild fields (adjust as needed)
    int_parent = INTParent(child_length=0, childs=1, next_header=0x01)
    # int_child = INTChild(id_switch=1, ingress_port=2, egress_port=3, timestamp=123456789, next_header=0x00, enq_qdepth=0, pkt_length=100, padding=0)

    print("sending on interface {} to IP addr {}".format(iface, str(addr)))
    pkt = Ether(src=get_if_hwaddr(iface), dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst=addr) / int_parent / TCP(dport=1234, sport=random.randint(49152,65535)) / message

    pkt.show2()
    sendp(pkt, iface=iface, verbose=False)


if __name__ == "__main__":
    main()
