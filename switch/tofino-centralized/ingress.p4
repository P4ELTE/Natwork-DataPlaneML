control MyIngress(inout headers_t hdr,
                inout ingress_user_meta_t user_meta,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    action flow_action_drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    action flow_action_port_forward_within_network(WidePortId_t egress_port, macAddr_t dst_mac) {
        ig_tm_md.ucast_egress_port = (PortId_t) egress_port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dst_mac;
    }

    action flow_action_port_forward_outside_network(WidePortId_t egress_port, macAddr_t dst_mac) {
        flow_action_port_forward_within_network(egress_port, dst_mac);

        //Restore the original packet
        hdr.ethernet.etherType = hdr.classified.etherType;
        hdr.classified.setInvalid();
    }

    //Executes an action based on the flow's label
    table flow_action_table {
        key = { hdr.classified.label: exact; }
        actions = { flow_action_drop; flow_action_port_forward_outside_network; flow_action_port_forward_within_network; }
        size = VALID_LABEL_COUNT + 1;
        default_action = flow_action_drop();
    }

    apply {
        if (hdr.classified.isValid()) {
            //Forward to the correct destination based on the label
            flow_action_table.apply();
        } else if (hdr.ethernet.etherType == ETHER_TYPE_IPV4) {
            //Forward to the control plane. The multicast group allows the control plane to specify the egress port.
            ig_tm_md.mcast_grp_a = 42;
        } else {
            //Drop packets we can't process
            ig_dprsr_md.drop_ctl = 1;
        }
    }
}
