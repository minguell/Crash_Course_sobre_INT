#!/usr/bin/env python3
import os
import sys

from scapy.all import (
    TCP,
    FieldLenField,
    FieldListField,
    IntField,
    IPOption,
    ShortField,
    get_if_list,
    sniff,
)
from scapy.layers.inet import _IPOption_HDR

from INT_headers import INTParent, INTChild


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


class IPOption_MRI(IPOption):
    name = "MRI"
    option = 31
    fields_desc = [
        _IPOption_HDR,
        FieldLenField(
            "length", None, fmt="B", length_of="swids", adjust=lambda pkt, l: l + 4
        ),
        ShortField("count", 0),
        FieldListField(
            "swids", [], IntField("", 0), length_from=lambda pkt: pkt.count * 4
        ),
    ]


# def handle_pkt(pkt):
#     if INTParent in pkt and INTChild in pkt and (TCP in pkt and pkt[TCP].dport == 1234):
#         print("got a packet")
#         pkt.show2()
#         #    hexdump(pkt)
#         sys.stdout.flush()


# def handle_pkt(pkt):
#     if INTParent in pkt and INTChild in pkt and (TCP in pkt and pkt[TCP].dport == 1234):
#         print("got a packet")
#         print()

#         int_parent = pkt[INTParent]
#         print("=== INTParent ===")
#         for field in int_parent.fields_desc:
#             print(f"  {field.name} = {getattr(int_parent, field.name)}")
#         print()

#         int_childs = []
#         current = int_parent.payload
#         while isinstance(current, INTChild):
#             int_childs.append(current)
#             current = current.payload

#         for idx, child in enumerate(int_childs):
#             print(f"=== INTChild #{idx} ===")
#             for field in child.fields_desc:
#                 print(f"  {field.name} = {getattr(child, field.name)}")
#             print()

#         payload = None
#         if hasattr(current, 'load'):
#             payload = current.load
#         elif hasattr(current, 'payload') and hasattr(current.payload, 'load'):
#             payload = current.payload.load
#         if payload is not None:
#             print("=== Payload ===")
#             print(payload.decode())
#         else:
#             print("=== Payload ===")
#             print(bytes(current))
#         sys.stdout.flush()


def handle_pkt(pkt):
    if INTParent in pkt and INTChild in pkt and (TCP in pkt and pkt[TCP].dport == 1234):
        print("got a packet")
        print()

        int_parent = pkt[INTParent]
        print("=== INTParent ===")
        for field in int_parent.fields_desc:
            print(f"  {field.name} = {getattr(int_parent, field.name)}")
        print()

        # Checa o campo de overflow
        mtu_overflow = getattr(int_parent, "mtu_overflow", 0)
        print("=== MTU Overflow Check ===")
        if mtu_overflow == 0:
            print("Todos os dados de telemetria foram coletados (sem estouro de MTU).")
        else:
            print("ATENÇÃO: Houve estouro de MTU em algum switch!")
            print("Dados de telemetria podem estar incompletos.")
        print("==========================")
        print()

        int_childs = []
        current = int_parent.payload
        while isinstance(current, INTChild):
            int_childs.append(current)
            current = current.payload

        for idx, child in enumerate(int_childs):
            print(f"=== INTChild #{idx} ===")
            for field in child.fields_desc:
                print(f"  {field.name} = {getattr(child, field.name)}")
            print()

        payload = None
        if hasattr(current, "load"):
            payload = current.load
        elif hasattr(current, "payload") and hasattr(current.payload, "load"):
            payload = current.payload.load
        if payload is not None:
            print("=== Payload ===")
            print(payload.decode())
        else:
            print("=== Payload ===")
            print(bytes(current))
        sys.stdout.flush()


def main():
    ifaces = [i for i in os.listdir("/sys/class/net/") if "eth" in i]
    iface = ifaces[0]
    print("sniffing on %s" % iface)
    sys.stdout.flush()
    sniff(iface=iface, prn=lambda x: handle_pkt(x))


if __name__ == "__main__":
    main()
