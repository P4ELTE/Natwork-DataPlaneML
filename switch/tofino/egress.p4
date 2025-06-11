control MyEgress(inout headers_t hdr,
               inout egress_user_meta_t user_meta,
               in egress_intrinsic_metadata_t eg_intr_md,
               in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
               inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
               inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) {
    apply {
        hdr.i2e.setInvalid();  // All relevant information has already been extracted

        //Handle reporting, monitoring
        if (hdr.reporting.isValid()) {
            //Only send the report header if this packet is really destined for the CPU

            //egress_rid_first is incorrectly set to 0 even for copy_to_cpu; this is a workaround
            //if (eg_intr_md.egress_rid == 0 && eg_intr_md.egress_rid_first == 1) {
            if (eg_intr_md.egress_port == 192 || eg_intr_md.egress_port == 64) {
                //Unicast packet, destined for the CPU
                // We do not set the destination MAC address here, therefore the recipient mustn't validate it
                // We assume that the reporting header comes directly after the ethernet header
                hdr.ethernet.etherType = ETHER_TYPE_REPORTING;
            } else {
                //Unicast packet, not destined for the CPU
                hdr.reporting.setInvalid();
            }
        }
    }
}
