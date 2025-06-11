#include <core.p4>
#include <tna.p4>

typedef bit<16> etherType_t;
typedef bit<48> macAddr_t;

typedef bit<32> ip4Addr_t;
typedef bit<8> protocol_t;

const etherType_t ETHER_TYPE_IPV4 = 0x0800; //2048

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    etherType_t etherType;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    protocol_t protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

struct headers_t {
    ethernet_t ethernet;
    ipv4_t ipv4;
}

struct user_meta_t {}

parser IngressParser(packet_in packet,
                     out headers_t hdr,
                     out user_meta_t user_meta,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);
        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHER_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition accept;
    }
}

control Ingress(inout headers_t hdr,
                inout user_meta_t user_meta,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    apply {
        ig_tm_md.ucast_egress_port = 192;
    }
}

control IngressDeparser(packet_out packet,
                        inout headers_t hdr,
                        in user_meta_t user_meta,
                        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    Checksum() ipv4_csum;

    apply {
        /*if (hdr.ipv4.isValid()) {
            hdr.ipv4.hdrChecksum = ipv4_csum.update({hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn,
                    hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl,
                    hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr});
        }*/

        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

parser EgressParser(packet_in packet,
                    out headers_t hdr,
                    out user_meta_t user_meta,
                    out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        packet.extract(eg_intr_md);
        transition accept;
    }
}

control Egress(inout headers_t hdr,
               inout user_meta_t user_meta,
               in egress_intrinsic_metadata_t eg_intr_md,
               in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply {}
}

control EgressDeparser(packet_out packet,
                       inout headers_t hdr,
                       in user_meta_t user_meta,
                       in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipeline;

Switch(pipeline) main;
