#include <core.p4>
#include <psa.p4>

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
struct resubmit_meta_t {}
struct recirculate_meta_t {}
struct normal_meta_t {}
struct clone_i2e_meta_t {}
struct clone_e2e_meta_t {}

control CommonDeparserImpl(packet_out packet,
                           inout headers_t hdr) {

    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.ipv4);
    }
}

parser IngressParserImpl(packet_in packet,
                         out headers_t hdr,
                         inout user_meta_t user_meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in resubmit_meta_t resubmit_meta,
                         in recirculate_meta_t recirculate_meta) {

    state start {
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

control IngressDeparserImpl(packet_out packet,
                            out clone_i2e_meta_t clone_i2e_meta,
                            out resubmit_meta_t resubmit_meta,
                            out normal_meta_t normal_meta,
                            inout headers_t hdr,
                            in user_meta_t user_meta,
                            in psa_ingress_output_metadata_t istd) {

    CommonDeparserImpl() deparser;

    apply {
        deparser.apply(packet, hdr);
    }
}

parser EgressParserImpl(packet_in packet,
                        out headers_t hdr,
                        inout user_meta_t user_meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in normal_meta_t normal_meta,
                        in clone_i2e_meta_t clone_i2e_meta,
                        in clone_e2e_meta_t clone_e2e_meta) {

    state start {
        transition accept;
    }
}

control EgressDeparserImpl(packet_out packet,
                           out clone_e2e_meta_t clone_e2e_meta,
                           out recirculate_meta_t recirculate_meta,
                           inout headers_t hdr,
                           in user_meta_t user_meta,
                           in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd) {

    CommonDeparserImpl() deparser;

    apply {
        deparser.apply(packet, hdr);
    }
}

control Ingress(inout headers_t hdr,
                    inout user_meta_t user_meta,
                    in psa_ingress_input_metadata_t istd,
                    inout psa_ingress_output_metadata_t ostd) {

    action l3_forward_set(PortId_t egress_port, macAddr_t dst_mac) {
        send_to_port(ostd, egress_port);
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dst_mac;
    }

    table l3_forward {
        key = { hdr.ipv4.dstAddr: exact; }
        actions = { l3_forward_set; }
        size = 256;
    }

    Hash<bit<16>>(PSA_HashAlgorithm_t.ONES_COMPLEMENT16) hash_csum16;

    apply {
        if (!hdr.ipv4.isValid() || hdr.ipv4.ttl == 1) {
            ingress_drop(ostd);
        } else {
            hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
            hdr.ipv4.hdrChecksum = hash_csum16.get_hash({hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn,
                    hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl,
                    hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr});

            if (l3_forward.apply().miss) {
                ingress_drop(ostd);
            }
        }
    }
}

control Egress(inout headers_t hdr,
                   inout user_meta_t user_meta,
                   in psa_egress_input_metadata_t istd,
                   inout psa_egress_output_metadata_t ostd) {

    apply {}
}

IngressPipeline(IngressParserImpl(), Ingress(), IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(), Egress(), EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
