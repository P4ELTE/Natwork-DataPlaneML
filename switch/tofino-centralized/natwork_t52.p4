#include <core.p4>
#include <tna.p4>

#include "types.p4"
#include "headers.p4"
#include "parsers.p4"
#include "ingress.p4"
#include "egress.p4"

Pipeline(
    MyIngressParser(),
    MyIngress(),
    MyIngressDeparser(),
    MyEgressParser(),
    MyEgress(),
    MyEgressDeparser()
) pipeline;

Switch(pipeline) main;
