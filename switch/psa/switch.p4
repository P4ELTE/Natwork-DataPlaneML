#include <core.p4>
#include <psa.p4> //https://raw.githubusercontent.com/p4lang/p4-spec/main/p4-16/psa/psa.p4

#include "config.p4"
#include "types.p4"
#include "headers.p4"
#include "parsers.p4"
#include "ingress.p4"
#include "egress.p4"

IngressPipeline(MyIngressParser(), MyIngress(), MyIngressDeparser()) ip;

EgressPipeline(MyEgressParser(), MyEgress(), MyEgressDeparser()) ep;

PSA_Switch(ip, PacketReplicationEngine(), ep, BufferingQueueingEngine()) main;
