/* -*- P4_16 -*- */
#include <core.p4>
#include <v1model.p4>

const bit<16> TYPE_IPV4 = 0x800;
const bit<16> TYPE_INT_PARENT = 0x111;
const bit<16> TYPE_INT_CHILD = 0x666;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct metadata {
    bit<8> int_hop_count;      // How many INT children have been added so far (for internal logic)
    bit<1> is_int_packet;      // Flag: is this packet being monitored by INT?
    bit<1> mtu_overflow_flag;   // For the MTU bonus: set if the INT header would overflow the MTU
}

header int_parent_t{
    bit<32> Child_Length;
    bit<32> Childs;
    //* Outros Dados*//
}


header int_child_t{
    bit<32> ID_Switch;
    bit<9> Porta_Entrada;
    bit<9> Porta_Saida;
    bit<48> Timestamp;
    bit<16> next_header;        // Indica o próximo cabeçalho (ex.: IPv4)
    bit<19> enq_qdepth;      // Profundidade da fila de entrada
    bit<32> pkt_length;      // Comprimento do pacote
    //* Outros Dados *//
    bit<3> padding; // O tamanho do cabecalho em bits deve ser multiplo de 8
}

const bit<8> MAX_INT_CHILD = 8;

// Add to the headers struct:
struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    int_parent_t int_parent;
    int_child_t  int_child;
}

// struct headers {
//     ethernet_t   ethernet;
//     ipv4_t       ipv4;
// }

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
            TYPE_INT_PARENT: parse_int_parent; // Se for tipo INT Pai, vai para parse_int_parent
            TYPE_IPV4: parse_ipv4;       // Se for IPv4, vai para parse_ipv4
            default: accept;
        }
    }

    // Estado para processar pacotes IPv4
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }

    // Estado para processar o cabeçalho INT Pai
    state parse_int_parent {
        packet.extract(hdr.int_parent);
        transition parse_int_child;
    }

    // Estado para processar o cabeçalho INT Filho
    state parse_int_child {
        packet.extract(hdr.int_child);
        transition select(hdr.int_child.next_header) {
            TYPE_INT_CHILD: parse_int_child; // Se houver mais filhos, processa o próximo
            TYPE_IPV4: parse_ipv4;           // Caso contrário, processa IPv4
            default: accept;
        }
    }
}



// parser MyParser(packet_in packet,
//                 out headers hdr,
//                 inout metadata meta,
//                 inout standard_metadata_t standard_metadata) {

//     state start {
//         transition parse_ethernet;
//     }

//     state parse_ethernet {
//         packet.extract(hdr.ethernet);
//         transition select(hdr.ethernet.etherType) {
//             TYPE_IPV4: parse_ipv4;
//             default: accept;
//         }
//     }

//     state parse_ipv4 {
//         packet.extract(hdr.ipv4);
//         transition accept;
//     }

// }

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

    action add_int_parent() {
        hdr.int_parent.setValid();
        hdr.int_parent.Child_Length = 0;
        hdr.int_parent.Childs = 0;
    }

    action add_int_child(
        bit<9> porta_entrada,
        bit<9> porta_saida,
        bit<48> timestamp,
        bit<19> enq_qdepth,
        bit<32> pkt_length
    ) {
        hdr.int_child.setValid();
        hdr.int_child.ID_Switch = (bit<32>)porta_entrada;
        hdr.int_child.Porta_Entrada = porta_entrada;
        hdr.int_child.Porta_Saida = porta_saida;
        hdr.int_child.Timestamp = timestamp;
        hdr.int_child.enq_qdepth = enq_qdepth;
        hdr.int_child.pkt_length = pkt_length;
        hdr.int_parent.Childs = hdr.int_parent.Childs + 1;
        hdr.int_child.next_header = TYPE_IPV4;
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
        }
        
        const bit<32> MTU = 1500;
        const bit<32> INT_CHILD_SIZE = 21; // tamanho em bytes do seu cabeçalho int_child_t
        
        if ((standard_metadata.packet_length + INT_CHILD_SIZE) > MTU) {
            meta.mtu_overflow_flag = 1;
            // Não adicione o filho INT!
        } else {
            meta.mtu_overflow_flag = 0;

            if (hdr.int_parent.isValid()) {
            // Se o cabeçalho INT Pai já existe, adiciona um novo filho
            add_int_child(
                standard_metadata.ingress_port,
                standard_metadata.egress_spec,
                standard_metadata.ingress_global_timestamp,
                standard_metadata.enq_qdepth,
                standard_metadata.packet_length
            );
            meta.int_hop_count = meta.int_hop_count + 1;

            } else {
                // Caso contrário, cria um novo cabeçalho INT Pai e um Filho
                add_int_parent();
                add_int_child(
                    standard_metadata.ingress_port,
                    standard_metadata.egress_spec,
                    standard_metadata.ingress_global_timestamp,
                    standard_metadata.enq_qdepth,
                    standard_metadata.packet_length
                );
                meta.int_hop_count = 0; // First child just added
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
        packet.emit(hdr.ipv4);
        // packet.emit(hdr.ethernet);  // Emite o cabeçalho Ethernet
        // packet.emit(hdr.ipv4);      // Emite o cabeçalho IPv4

        // // Emite o cabeçalho int_pai se for válido
        // packet.emit(hdr.int_pai);

        // // Emite o cabeçalho int_filho se for válido
        // packet.emit(hdr.int_filho);
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
