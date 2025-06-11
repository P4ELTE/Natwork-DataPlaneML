#include <core.p4>
#include <tna.p4>

header test_t {
    bit<8> test;
}
struct headers_t {
    test_t test;
}

typedef bit<16> value_t;
struct user_meta_t {
    value_t value_1;
    value_t value_2;
    value_t value_3;
    value_t value_4;
    value_t value_5;
    value_t value_6;
    value_t value_7;
    value_t value_8;
    value_t value_9;
    value_t value_10;
    value_t value_11;
    value_t value_12;
    value_t value_13;
    value_t value_14;
    value_t value_15;
    value_t value_16;
}

parser IngressParser(packet_in pkt,
                     out headers_t hdr,
                     out user_meta_t meta,
                     out ingress_intrinsic_metadata_t ig_intr_md) {
    state start {
        transition accept;
    }
}

control Ingress(inout headers_t hdr,
                inout user_meta_t user_meta,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action range_test_action() {
        hdr.test.setValid();
        hdr.test.test = 42;
    }
    table range_test {
        key = {
            user_meta.value_1: range; user_meta.value_2: range; user_meta.value_3: range; user_meta.value_4: range;
            user_meta.value_5: range; user_meta.value_6: range; //user_meta.value_7: range; user_meta.value_8: range;
//            user_meta.value_9: range; user_meta.value_10: range; user_meta.value_11: range; user_meta.value_12: range;
//            user_meta.value_13: range;
        }
        actions = { range_test_action; }
        size = 12000;
    }

    apply {
        range_test.apply();
    }
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
