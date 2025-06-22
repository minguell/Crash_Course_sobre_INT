/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x0800;
const bit<16> TYPE_INT_PARENT = 0xFE00;
const bit<16> TYPE_INT_CHILD = 0xFE01;

const bit<32> MTU = 1500;
// const bit<32> INT_CHILD_SIZE = 21; // Size in bytes of int_child_t header (original)
const bit<32> INT_CHILD_SIZE = 16; // Size in bytes of int_child_t header (adjust accordingly)

#define MAX_CHILDS 91 // Adjust to fit MTU

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>      egressSpec_t;
typedef bit<48>     macAddr_t;
typedef bit<32>     ip4Addr_t;

header ethernet_t {
    macAddr_t       dstAddr;
    macAddr_t       srcAddr;
    bit<16>         etherType;
}

header ipv4_t {
    bit<4>          version;
    bit<4>          ihl;
    bit<8>          diffserv;
    bit<16>         totalLen;
    bit<16>         identification;
    bit<3>          flags;
    bit<13>         fragOffset;
    bit<8>          ttl;
    bit<8>          protocol;
    bit<16>         hdrChecksum;
    ip4Addr_t       srcAddr;
    ip4Addr_t       dstAddr;
}

struct metadata {
    bit<8>          int_hop_count;
    bit<1>          is_int_packet;
    bit<1>          mtu_overflow_flag;
}


header int_parent_t{
    bit<32>         child_length;
    bit<32>         childs;
    bit<16>         next_header;
    bit<8>          mtu_overflow;
}

header int_child_t{
    bit<32>         id_switch;
    bit<48>         timestamp;
    bit<32>         pkt_length;
    // bit<9>       ingress_port;       // Issue with field not multiple of 8 bits
    // bit<9>       egress_port;        // Issue with field not multiple of 8 bits
    // bit<19>      enq_qdepth;         // Issue with field not multiple of 8 bits
    // bit<3>       padding;            // Issue with field not multiple of 8 bits (The header size must be a multiple of 8 bits)
    bit<16>         next_header;
}

struct headers {
    ethernet_t                  ethernet;
    int_parent_t                int_parent;
    int_child_t[MAX_CHILDS]     int_childs; // Fixed size array for INT children (may be unessary)
    ipv4_t                      ipv4;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                inout metadata meta,
                inout standard_metadata_t standard_metadata) {

    state start {
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            TYPE_INT_PARENT: parse_int_parent;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    // State to process the INT Parent header
    state parse_int_parent {
        packet.extract(hdr.int_parent);
        transition select(hdr.int_parent.next_header) {
            TYPE_INT_CHILD: parse_int_child;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    // State to process the INT Child header
    state parse_int_child {
        packet.extract(hdr.int_childs.next);
        transition select(hdr.int_childs.last.next_header) {
            TYPE_INT_CHILD: parse_int_child;
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

}

/*************************************************************************
************   C H E C K S U M    V E R I F I C A T I O N   *************
*************************************************************************/

control MyVerifyChecksum(inout headers hdr, inout metadata meta) {
    apply {  }
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(macAddr_t dstAddr, egressSpec_t port) {
        standard_metadata.egress_spec = port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dstAddr;
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action add_int_parent_and_first_child(
        bit<9> ingress_port,
        bit<9> egress_port,
        bit<48> timestamp,
        bit<19> enq_qdepth,
        bit<32> pkt_length
    ) {
        hdr.int_parent.setValid();
        hdr.int_parent.child_length = INT_CHILD_SIZE;
        hdr.int_parent.childs = 1;
        hdr.int_parent.next_header = TYPE_INT_CHILD;
        hdr.int_parent.mtu_overflow = 0;
        hdr.ethernet.etherType = TYPE_INT_PARENT;

        hdr.int_childs[0].setValid();
        hdr.int_childs[0].id_switch = (bit<32>)ingress_port;
        hdr.int_childs[0].timestamp = timestamp;
        hdr.int_childs[0].pkt_length = pkt_length;
        // hdr.int_childs[0].ingress_port = ingress_port;   // Issue with field not multiple of 8 bits
        // hdr.int_childs[0].egress_port = egress_port;     // Issue with field not multiple of 8 bits
        // hdr.int_childs[0].enq_qdepth = enq_qdepth;       // Issue with field not multiple of 8 bits
        // hdr.int_childs[0].padding = 0;                   // Issue with field not multiple of 8 bits
        hdr.int_childs[0].next_header = TYPE_IPV4;
    }

    action add_int_child(
        bit<9>      ingress_port,
        bit<9>      egress_port,
        bit<48>     timestamp,
        bit<19>     enq_qdepth,
        bit<32>     pkt_length
    ) {
        bit<32> idx = hdr.int_parent.childs;

        if (idx > 0) {
            hdr.int_childs[idx - 1].next_header = TYPE_INT_CHILD;
        }

        hdr.int_childs[idx].setValid();
        hdr.int_childs[idx].id_switch = (bit<32>)ingress_port;
        hdr.int_childs[idx].timestamp = timestamp;
        hdr.int_childs[idx].pkt_length = pkt_length;
        // hdr.int_childs[idx].ingress_port = ingress_port; // Issue with field not multiple of 8 bits
        // hdr.int_childs[idx].egress_port = egress_port;   // Issue with field not multiple of 8 bits
        // hdr.int_childs[idx].enq_qdepth = enq_qdepth;     // Issue with field not multiple of 8 bits
        // hdr.int_childs[idx].padding = 0;                 // Issue with field not multiple of 8 bits
        hdr.int_childs[idx].next_header = TYPE_IPV4;

        hdr.int_parent.childs = hdr.int_parent.childs + 1;
        hdr.int_parent.child_length = hdr.int_parent.child_length + INT_CHILD_SIZE;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = drop();
    }

    apply {
        if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
            if ((standard_metadata.packet_length + INT_CHILD_SIZE) > MTU) {
                meta.mtu_overflow_flag = 1;
                if (!hdr.int_parent.isValid()) {
                    hdr.int_parent.mtu_overflow = 1;
                }
            } 
            else {
                meta.mtu_overflow_flag = 0;
                if (!hdr.int_parent.isValid()) {
                    // The first INT parent header has a child
                    add_int_parent_and_first_child(
                        standard_metadata.ingress_port,
                        standard_metadata.egress_spec,
                        standard_metadata.ingress_global_timestamp,
                        standard_metadata.enq_qdepth,
                        standard_metadata.packet_length
                    );
                    meta.int_hop_count = 0;
                }
                else {
                    if (hdr.int_parent.childs < MAX_CHILDS) {
                        add_int_child(
                            standard_metadata.ingress_port,
                            standard_metadata.egress_spec,
                            standard_metadata.ingress_global_timestamp,
                            standard_metadata.enq_qdepth,
                            standard_metadata.packet_length
                        );
                        meta.int_hop_count = meta.int_hop_count + 1;
                    } else {
                        // Optionally set overflow flag or drop
                        // meta.mtu_overflow_flag = 1;
                        // drop();
                    }
                }
            }
        }
    }
}

/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyEgress(inout headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    apply {  }
}

/*************************************************************************
*************   C H E C K S U M    C O M P U T A T I O N   **************
*************************************************************************/

control MyComputeChecksum(inout headers  hdr, inout metadata meta) {
     apply {
        update_checksum(
        hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control MyDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.int_parent);
        packet.emit(hdr.int_childs);
        packet.emit(hdr.ipv4);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

V1Switch(
MyParser(),
MyVerifyChecksum(),
MyIngress(),
MyEgress(),
MyComputeChecksum(),
MyDeparser()
) main;
