#include <core.p4>
#include <tna.p4>

struct headers_t {}
struct user_meta_t {}

parser IngressParser(packet_in pkt,
                     out headers_t hdr,
                     out user_meta_t meta,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        transition accept;
    }
}

control Ingress(inout headers_t hdr,
                inout user_meta_t meta,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {
    apply {}
}

control IngressDeparser(packet_out pkt,
                        inout headers_t hdr,
                        in user_meta_t meta,
                        in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md) {
    apply {}
}

parser EgressParser(packet_in pkt,
                    out headers_t hdr,
                    out user_meta_t meta,
                    out egress_intrinsic_metadata_t eg_intr_md) {
    state start {
        transition accept;
    }
}

control Egress(inout headers_t hdr,
               inout user_meta_t meta,
               in egress_intrinsic_metadata_t eg_intr_md,
               in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply {}
}

control EgressDeparser(packet_out pkt,
                       inout headers_t hdr,
                       in user_meta_t meta,
                       in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {}
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
