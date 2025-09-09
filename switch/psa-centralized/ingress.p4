control MyIngress(inout headers_t hdr,
                    inout user_meta_t user_meta,
                    in psa_ingress_input_metadata_t istd,
                    inout psa_ingress_output_metadata_t ostd) {

    action flow_action_drop() {
        ingress_drop(ostd);
    }

    action flow_action_port_forward_within_network(PortId_t egress_port, macAddr_t dst_mac) {
        send_to_port(ostd, egress_port);
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dst_mac;
    }

    action flow_action_port_forward_outside_network(PortId_t egress_port, macAddr_t dst_mac) {
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
            //Forward to the control plane. We use a multicast group to allow the control plane to specify
            //  the egress port, because PSA_PORT_CPU doesn't seem to work.
            multicast(ostd, (MulticastGroup_t) (bit<32>) 42);
        } else {
            //Drop packets we can't process
            ingress_drop(ostd);
        }
    }
}
