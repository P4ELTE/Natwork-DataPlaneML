parser MyIngressParser(packet_in packet,
                     out headers_t hdr,
                     out ingress_user_meta_t user_meta,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);

        //The following values will be overwritten prior to being used; they are only set to supress warnings
        user_meta.flow_id = {0, 0, 0, 0, 0};
        user_meta.hashed_flow_id = 0;
        user_meta.mutated_hashed_flow_id = 0;
        user_meta.features = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        user_meta.reset_flow_data = 0;

        //Some of the following initial values are actually used (so it's important they are set to these exact values)
        user_meta.flow_data = {LABEL_NOT_SET};
        user_meta.rf = {LABEL_NOT_SET, 0, false, false};

        transition parse_ethernet;
    }

    state parse_ethernet {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
            ETHER_TYPE_INFERENCE: parse_inference;
            ETHER_TYPE_IPV4: parse_ipv4;
            default: reject;
        }
    }

    state parse_inference {
        packet.extract(hdr.inference);
        transition select(hdr.inference.etherType) {
            ETHER_TYPE_IPV4: parse_ipv4;
            default: reject;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPV4_PROTOCOL_TCP: parse_tcp;
            IPV4_PROTOCOL_UDP: parse_udp;
            default: parse_neither_tcp_nor_udp;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        user_meta.port_src = hdr.tcp.srcPort;
        user_meta.port_dst = hdr.tcp.dstPort;
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        user_meta.port_src = hdr.udp.srcPort;
        user_meta.port_dst = hdr.udp.dstPort;
        transition accept;
    }

    state parse_neither_tcp_nor_udp {
        user_meta.port_src = 0;
        user_meta.port_dst = 0;
        transition accept;
    }
}

control MyIngressDeparser(packet_out packet,
                        inout headers_t hdr,
                        in ingress_user_meta_t user_meta,
                        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    Checksum() ipv4_csum;

    apply {
        // TTL might have changed
        hdr.ipv4.hdrChecksum = ipv4_csum.update({hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn,
                hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl,
                hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr});

        packet.emit(hdr.i2e);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.reporting);
        packet.emit(hdr.inference);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}

parser MyEgressParser(packet_in packet,
                    out headers_t hdr,
                    out egress_user_meta_t user_meta,
                    out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        packet.extract(eg_intr_md);
        packet.extract(hdr.i2e);
        packet.extract(hdr.ethernet);
        transition select(hdr.i2e.reporting_header_valid) {
            1: parse_reporting;
            default: accept;
        }
    }

    state parse_reporting {
        packet.extract(hdr.reporting);
        transition accept;
    }
}

control MyEgressDeparser(packet_out packet,
                       inout headers_t hdr,
                       in egress_user_meta_t user_meta,
                       in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        packet.emit(hdr.i2e);
        packet.emit(hdr.ethernet);
        packet.emit(hdr.reporting);
        packet.emit(hdr.inference);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.tcp);
        packet.emit(hdr.udp);
    }
}
