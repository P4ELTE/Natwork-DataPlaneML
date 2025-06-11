control CommonDeparser(packet_out packet,
                           inout headers_t hdr) {

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

parser MyIngressParser(packet_in packet,
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
            ETHER_TYPE_INFERENCE: parse_inference;
            ETHER_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_inference {
        packet.extract(hdr.inference);
        transition select(hdr.inference.etherType) {
            ETHER_TYPE_IPV4: parse_ipv4;
            default: accept;
        }
    }

    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPV4_PROTOCOL_TCP: parse_tcp;
            IPV4_PROTOCOL_UDP: parse_udp;
            default: accept;
        }
    }

    state parse_tcp {
        packet.extract(hdr.tcp);
        transition accept;
    }

    state parse_udp {
        packet.extract(hdr.udp);
        transition accept;
    }
}

control MyIngressDeparser(packet_out packet,
                            out clone_i2e_meta_t clone_i2e_meta,
                            out resubmit_meta_t resubmit_meta,
                            out normal_meta_t normal_meta,
                            inout headers_t hdr,
                            in user_meta_t user_meta,
                            in psa_ingress_output_metadata_t istd) {

    CommonDeparser() deparser;

    apply {
        hdr.i2e.setValid();
        hdr.i2e.cpu_port = user_meta.cpu_port;
        hdr.i2e.reporting_header_valid = hdr.reporting.isValid();

        deparser.apply(packet, hdr);
    }
}

parser MyEgressParser(packet_in packet,
                        out headers_t hdr,
                        inout user_meta_t user_meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in normal_meta_t normal_meta,
                        in clone_i2e_meta_t clone_i2e_meta,
                        in clone_e2e_meta_t clone_e2e_meta) {

    state start {
        packet.extract(hdr.i2e);
        user_meta.cpu_port = hdr.i2e.cpu_port;

        packet.extract(hdr.ethernet);

        if (hdr.i2e.reporting_header_valid) {
            packet.extract(hdr.reporting);
        }

        hdr.i2e.setInvalid();
        transition accept;
    }
}

control MyEgressDeparser(packet_out packet,
                           out clone_e2e_meta_t clone_e2e_meta,
                           out recirculate_meta_t recirculate_meta,
                           inout headers_t hdr,
                           in user_meta_t user_meta,
                           in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd) {

    CommonDeparser() deparser;

    apply {
        deparser.apply(packet, hdr);
    }
}
