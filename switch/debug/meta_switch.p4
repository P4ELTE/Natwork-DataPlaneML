#include <core.p4>
#include <psa.p4>

struct headers_t {}
struct empty_meta_t {}

struct ingress_meta_t {}
struct egress_meta_t {}

control CommonDeparserImpl(packet_out packet,
                           inout headers_t hdr) {
    apply {}
}

parser IngressParserImpl(packet_in packet,
                         out headers_t hdr,
                         inout ingress_meta_t user_meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_meta_t resubmit_meta,
                         in empty_meta_t recirculate_meta) {
    state start {
        transition accept;
    }
}

control IngressDeparserImpl(packet_out packet,
                            out empty_meta_t clone_i2e_meta,
                            out empty_meta_t resubmit_meta,
                            out empty_meta_t normal_meta,
                            inout headers_t hdr,
                            in ingress_meta_t user_meta,
                            in psa_ingress_output_metadata_t istd) {
    CommonDeparserImpl() deparser;
    apply {
        deparser.apply(packet, hdr);
    }
}

parser EgressParserImpl(packet_in packet,
                        out headers_t hdr,
                        inout egress_meta_t user_meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in empty_meta_t normal_meta,
                        in empty_meta_t clone_i2e_meta,
                        in empty_meta_t clone_e2e_meta) {
    state start {
        transition accept;
    }
}

control EgressDeparserImpl(packet_out packet,
                           out empty_meta_t clone_e2e_meta,
                           out empty_meta_t recirculate_meta,
                           inout headers_t hdr,
                           in egress_meta_t user_meta,
                           in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd) {
    CommonDeparserImpl() deparser;
    apply {
        deparser.apply(packet, hdr);
    }
}

control Ingress(inout headers_t hdr,
                    inout ingress_meta_t user_meta,
                    in psa_ingress_input_metadata_t istd,
                    inout psa_ingress_output_metadata_t ostd) {
    apply {}
}

control Egress(inout headers_t hdr,
                   inout egress_meta_t user_meta,
                   in psa_egress_input_metadata_t istd,
                   inout psa_egress_output_metadata_t ostd) {
    apply {
        // Dummy code to make the egress pipeline non-empty
        if (istd.egress_port != PSA_PORT_CPU) {
            egress_drop(ostd);
        }
    }
}

IngressPipeline(IngressParserImpl(), Ingress(), IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(), Egress(), EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
