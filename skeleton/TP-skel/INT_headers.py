from scapy.all import *
from scapy.layers.inet import Ether, IP, TCP

TYPE_INT_PARENT = 0xFE00
TYPE_INT_CHILD = 0xFE01
TYPE_IPV4 = 0x0800


class INTParent(Packet):
    name = "INTParent"
    fields_desc = [
        IntField("child_length", 0),
        IntField("childs", 0),
        ShortField("next_header", 0),
    ]


class INTChild(Packet):
    name = "INTChild"
    fields_desc = [
        IntField("id_switch", 0),
        BitField("ingress_port", 0, 9),
        BitField("egress_port", 0, 9),
        BitField("timestamp", 0, 48),
        ShortField("next_header", 0),
        BitField("enq_qdepth", 0, 19),
        IntField("pkt_length", 0),
        BitField("padding", 0, 3),
    ]


# Bind layers: Ether -> INTParent -> INTChild -> IP
bind_layers(Ether, INTParent, type=TYPE_INT_PARENT)
bind_layers(INTParent, IP, next_header=TYPE_IPV4)

bind_layers(INTParent, INTChild, next_header=TYPE_INT_CHILD)
bind_layers(INTChild, INTChild, next_header=TYPE_INT_CHILD)
bind_layers(INTChild, IP, next_header=TYPE_IPV4)

# bind_layers(INTChild, TCP, next_header=6)  # 6 is TCP protocol number (???)
