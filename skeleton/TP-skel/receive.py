#!/usr/bin/env python3
import os
import sys

from INT_headers import INTParent, INTChild
from scapy.all import (
    TCP,
    # FieldLenField,
    # FieldListField,
    # IntField,
    # IPOption,
    # ShortField,
    get_if_list,
    sniff,
    # Packet,
    # BitField,
    # ByteField,
    # ShortField,
    # IntField,
    # LongField,
    # bind_layers,
    # Ether,
    # IP,
    get_if_list,
    sniff,
)


def get_if():
    ifs = get_if_list()
    iface = None
    for i in get_if_list():
        if "eth0" in i:
            iface = i
            break
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface


# class IPOption_MRI(IPOption):
#     name = "MRI"
#     option = 31
#     fields_desc = [
#         _IPOption_HDR,
#         FieldLenField(
#             "length", None, fmt="B", length_of="swids", adjust=lambda pkt, l: l + 4
#         ),
#         ShortField("count", 0),
#         FieldListField(
#             "swids", [], IntField("", 0), length_from=lambda pkt: pkt.count * 4
#         ),
#     ]


def handle_pkt(pkt):
    # if INTParent in pkt:
    #     print("### INT Parent ###")
    #     pkt[INTParent].show2()
    # if INTChild in pkt:
    #     print("### INT Child ###")
    #     int_child = pkt[INTChild]
    #     while int_child:
    #         int_child.show2()
    #         if hasattr(int_child, 'payload') and isinstance(int_child.payload, INTChild):
    #             int_child = int_child.payload
    #         else:
    #             break


    # if TCP in pkt and pkt[TCP].dport == 1234:
    #     print("got a packet")
    #     pkt.show2()
    #     #    hexdump(pkt)
    #     sys.stdout.flush()

    
    # if INTParent in pkt or INTChild in pkt or (TCP in pkt and pkt[TCP].dport == 1234):
        # print("got a packet")
        # if INTParent in pkt:
        #     print("### INT Parent ###")
        #     pkt[INTParent].show2()
        # if INTChild in pkt:
        #     print("### INT Children ###")
        #     int_child = pkt[INTChild]
        #     while int_child:
        #         int_child.show2()
        #         # Traverse possible stack of INTChild headers
        #         if hasattr(int_child, 'payload') and isinstance(int_child.payload, INTChild):
        #             int_child = int_child.payload
        #         else:
        #             break
        # if TCP in pkt:
        #     pkt.show2()
        # sys.stdout.flush()
        if INTParent in pkt or INTChild in pkt or (TCP in pkt and pkt[TCP].dport == 1234):
            print("got a packet")
            # if INTParent in pkt:
            #     pkt[INTParent].show2()
            # if TCP in pkt:
            #     pkt.show2()
            pkt.show2()
            sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir("/sys/class/net/") if "eth" in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface=iface, prn=lambda x: handle_pkt(x))


if __name__ == "__main__":
    main()
