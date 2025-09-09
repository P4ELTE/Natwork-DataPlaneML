parser MyIngressParser(packet_in packet,
                     out headers_t hdr,
                     out ingress_user_meta_t user_meta,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        packet.extract(ig_intr_md);
        packet.advance(PORT_METADATA_SIZE);
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
                        inout headers_t hdr,
                        in ingress_user_meta_t user_meta,
                        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.classified);
    }
}

parser MyEgressParser(packet_in packet,
                    out headers_t hdr,
                    out egress_user_meta_t user_meta,
                    out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        packet.extract(eg_intr_md);
        transition accept;
    }
}

control MyEgressDeparser(packet_out packet,
                       inout headers_t hdr,
                       in egress_user_meta_t user_meta,
                       in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.classified);
    }
}
