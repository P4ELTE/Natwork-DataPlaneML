control CommonDeparser(packet_out packet,
                           inout headers_t hdr) {

    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.classified);
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
            ETHER_TYPE_IPV4: accept;
            ETHER_TYPE_CLASSIFIED: parse_classified;
            default: accept;
        }
    }

    state parse_classified {
        packet.extract(hdr.classified);
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
