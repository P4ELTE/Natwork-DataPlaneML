control MyEgress(inout headers_t hdr,
                   inout user_meta_t user_meta,
                   in psa_egress_input_metadata_t istd,
                   inout psa_egress_output_metadata_t ostd) {

    apply {
        //eBPF-PSA: while the ingress and egress user meta must have the same type, data isn't transferred between them.
        //  Therefore make sure to only use user meta fields that have been assigned in the parser.

        //Handle reporting, monitoring
        if (hdr.reporting.isValid()) {
            //Only send the report header if this packet is really destined for the CPU
            if (istd.egress_port != user_meta.cpu_port) {
                hdr.reporting.setInvalid();
            } else {
                // We do not set the destination MAC address here, therefore the recipient mustn't validate it
                // We assume that the reporting header comes directly after the ethernet header
                hdr.ethernet.etherType = ETHER_TYPE_REPORTING;
            }
        }
    }
}
