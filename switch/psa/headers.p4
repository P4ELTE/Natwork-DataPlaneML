//Header for sending data from the ingress pipeline to the egress pipeline
//This is necessary because while the ingress and egress user meta must have the same type with eBPF-PSA,
//  the data isn't transferred between them. Therefore an alternative method is needed: headers.
header i2e_t {
    PortId_t cpu_port;
    bool reporting_header_valid;
    bit<7> padding; //Headers must be a multiple of 8 bits
}

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    etherType_t etherType;
}

//Header used to pass data related to inference (classification) between switches.
//The classification of flows is broken into subtasks, which are distributed among multiple switches.
//This header contains the sub-results computed by the subtasks finished by earlier switches on the packet's path.
header inference_t {
    etherType_t etherType; // The ether type of the rest of the packet

    //RF whose DTs should be executed. '0' means that no appropriate RF exists; the packet shouldn't be classified.
    //If this header isn't present, that means that the current switch should determine the RF to use.
    rf_id_t rf_id;

    dt_count_t executed_dt_count;  //Count of DTs that have already been computed and their results stored
    dt_bitflag_t executed_dt_bitflag;  //The i-th bit of this value is '1' iff the DT with id 'i' has been executed

    //When a DT is executed, the certainty value of the final node is added to corresponding field below
    certainty_sum_t certainty_sum_label_1;
    certainty_sum_t certainty_sum_label_2;
    #if VALID_LABEL_COUNT != 2
        #error "Source code doesn't match configuration; please check this error's source location."
    #endif
}

//Header used for reporting: when sending flows to the CPU, this header is sent (without any other headers or payload)
//The eBPF-PSA implementation does not support structs inside headers.
header reporting_t {
    //flow_id_t flow_id:
    ip4Addr_t flow_id_ip_lower;
    ip4Addr_t flow_id_ip_upper;
    protocol_t flow_id_protocol;
    protocol_port_t flow_id_port_at_lower;
    protocol_port_t flow_id_port_at_upper;
    //features_t features: Flow features at the current length
    feature_count_t count;
    feature_iat_t iat_min;
    feature_iat_t iat_max;
    feature_iat_t iat_avg;
    feature_length_t length_min;
    feature_length_t length_max;
    feature_length_t length_avg;
    feature_length_sum_t length_sum;
    feature_count_tcp_t count_tcp_syn;
    feature_count_tcp_t count_tcp_ack;
    feature_count_tcp_t count_tcp_psh;
    feature_count_tcp_t count_tcp_fin;
    feature_count_tcp_t count_tcp_rst;
    feature_count_tcp_t count_tcp_ece;
    feature_duration_t duration;
    protocol_port_t port_client;
    protocol_port_t port_server;
    feature_length_t length_current;
    //label_t accepted_label: Label assigned to the flow, if any: first verdict_label with high enough certainty
    label_t accepted_label;
    //label_t latest_label: Label assigned to the flow (if any) at the current flow length with the current features
    label_t latest_label;
    //certainty_sum_t latest_label_certainty_sum: Certainty of latest_label (if label is set)
    certainty_sum_t latest_label_certainty_sum;
    //dt_count_t latest_label_dt_count: Count of DTs that contributed to the certainty sum
    dt_count_t latest_label_dt_count;
}

header ipv4_t {
    bit<4> version;
    bit<4> ihl;
    bit<6> dscp;
    bit<2> ecn;
    bit<16> totalLen;
    bit<16> identification;
    bit<3> flags;
    bit<13> fragOffset;
    bit<8> ttl;
    protocol_t protocol;
    bit<16> hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

header tcp_t {
    protocol_port_t srcPort;
    protocol_port_t dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4> dataOffset;
    bit<4> res;
    bit<1> cwr;
    bit<1> ece;
    bit<1> urg;
    bit<1> ack;
    bit<1> psh;
    bit<1> rst;
    bit<1> syn;
    bit<1> fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

header udp_t {
    protocol_port_t srcPort;
    protocol_port_t dstPort;
    bit<16> udplen;
    bit<16> udpchk;
}

//If needed, separate ingress and egress headers are possible
struct headers_t {
    i2e_t i2e;
    ethernet_t ethernet;
    reporting_t reporting;
    inference_t inference;
    ipv4_t ipv4;
    tcp_t tcp;
    udp_t udp;
}
