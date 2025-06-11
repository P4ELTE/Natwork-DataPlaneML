#include <core.p4>
#include <psa.p4>

struct headers_t {}
struct empty_meta_t {}
struct clone_i2e_meta_t {
    bit<8> test;
}

control CommonDeparserImpl(packet_out packet,
                           inout headers_t hdr) {
    apply {}
}

parser IngressParserImpl(packet_in packet,
                         out headers_t hdr,
                         inout empty_meta_t user_meta,
                         in psa_ingress_parser_input_metadata_t istd,
                         in empty_meta_t resubmit_meta,
                         in empty_meta_t recirculate_meta) {
    state start {
        transition accept;
    }
}

control IngressDeparserImpl(packet_out packet,
                            out clone_i2e_meta_t clone_i2e_meta,
                            out empty_meta_t resubmit_meta,
                            out empty_meta_t normal_meta,
                            inout headers_t hdr,
                            in empty_meta_t user_meta,
                            in psa_ingress_output_metadata_t istd) {
    CommonDeparserImpl() deparser;
    apply {
        if (psa_clone_i2e(istd)) {
            clone_i2e_meta.test = 42;
        }
        deparser.apply(packet, hdr);
    }
}

parser EgressParserImpl(packet_in packet,
                        out headers_t hdr,
                        inout empty_meta_t user_meta,
                        in psa_egress_parser_input_metadata_t istd,
                        in empty_meta_t normal_meta,
                        in clone_i2e_meta_t clone_i2e_meta,
                        in empty_meta_t clone_e2e_meta) {
    state start {
        transition accept;
    }
}

control EgressDeparserImpl(packet_out packet,
                           out empty_meta_t clone_e2e_meta,
                           out empty_meta_t recirculate_meta,
                           inout headers_t hdr,
                           in empty_meta_t user_meta,
                           in psa_egress_output_metadata_t istd,
                           in psa_egress_deparser_input_metadata_t edstd) {
    CommonDeparserImpl() deparser;
    apply {
        deparser.apply(packet, hdr);
    }
}

control Ingress(inout headers_t hdr,
                    inout empty_meta_t user_meta,
                    in psa_ingress_input_metadata_t istd,
                    inout psa_ingress_output_metadata_t ostd) {
    apply {
        ostd.clone = true;
        ostd.clone_session_id = PSA_CLONE_SESSION_TO_CPU; // This is a constant defined in psa.p4
    }
}

control Egress(inout headers_t hdr,
                   inout empty_meta_t user_meta,
                   in psa_egress_input_metadata_t istd,
                   inout psa_egress_output_metadata_t ostd) {
    apply {}
}

IngressPipeline(IngressParserImpl(), Ingress(), IngressDeparserImpl()) ip;

EgressPipeline(EgressParserImpl(), Egress(), EgressDeparserImpl()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
