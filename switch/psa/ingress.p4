#define MIN(x,y) (x <= y ? x : y)
#define MAX(x,y) (x >= y ? x : y)

control MyIngress(inout headers_t hdr,
                    inout user_meta_t user_meta,
                    in psa_ingress_input_metadata_t istd,
                    inout psa_ingress_output_metadata_t ostd) {

    Hash<bit<32>>(PSA_HashAlgorithm_t.CRC32) hash_crc32;
    Hash<bit<16>>(PSA_HashAlgorithm_t.ONES_COMPLEMENT16) hash_csum16;

    ////////////////////////////////////
    // FLOW ID HASH BASED PERSISTENCE //
    ////////////////////////////////////

//Creates a register of the specified name and value type, to be indexed by the hashed flow id
#define HASH_REGISTER(TYPE, NAME) Register<TYPE, hashed_flow_id_t>(1 << HASHED_FLOW_ID_WIDTH, 0) NAME

//Executes the following: VAR := REG.read(hashed_flow_id)
#define HASH_READ(REG, VAR) VAR = REG.read(user_meta.hashed_flow_id);

//Executes the following: REG.write(VAR)
#define HASH_WRITE(REG, VAR) REG.write(user_meta.hashed_flow_id, VAR);

//Executes the following: VAR := REG.read(hashed_flow_id) ; VAR := VAL ; REG.write(VAR)
#define HASH_READ_UPDATE_WRITE(REG, VAR, VAL) \
        VAR = REG.read(user_meta.hashed_flow_id); \
        VAR = VAL; \
        REG.write(user_meta.hashed_flow_id, VAR);

//Executes the following: VAR := REG.read(hashed_flow_id) ; VAR := moving_average(VAR,VAL) ; REG.write(VAR)
//  WIDTH is the bit width of the VAR and VAL variables.
#define HASH_READ_AVERAGE_WRITE(REG, VAR, VAL, WIDTH) \
        VAR = REG.read(user_meta.hashed_flow_id); \
        if (VAR == 0) { \
            VAR = VAL; /* first value */ \
        } else { \
            /* VAR = VAR + (signed_diff >> FEATURE_AVERAGE_SMOOTHING) */ \
            /* VAR = VAR + ((bit<WIDTH>) ((((int<WIDTH>) VAL) - ((int<WIDTH>) VAR)) >> FEATURE_AVERAGE_SMOOTHING)); */ \
            /* The solution above didn't work, because p4c-psa doesn't seem to support signed integers. */ \
            /* VAR = ((VAR * (2^X-1)) >> X) + (VAL >> X) */ \
            /* Arithmetic on more than 64 bits is unsupported. */ \
            VAR = (bit<WIDTH>) ((((bit<64>) VAR) * ((((bit<64>) 1) << FEATURE_AVERAGE_SMOOTHING) - 1)) >> FEATURE_AVERAGE_SMOOTHING) \
                + (VAL >> FEATURE_AVERAGE_SMOOTHING); \
        } \
        REG.write(user_meta.hashed_flow_id, VAR);

//Executes the following: VAR := REG.read(hashed_flow_id) ; VAR = VAR |+| VAL ; REG.write(VAR)
//  (Saturating addition: if the result is larger than the maximum value, the maximum value is used)
#define HASH_READ_SUM_WRITE(REG, VAR, VAL, MAX) \
        VAR = REG.read(user_meta.hashed_flow_id); \
        if (VAR + VAL < VAR) { VAR = MAX; } \
        else { VAR = VAR + VAL; } \
        REG.write(user_meta.hashed_flow_id, VAR);

//Executes the following: VAR := VAL; REG.write(VAR)
#define HASH_SET_WRITE(REG, VAR, VAL) \
        VAR = VAL; REG.write(user_meta.hashed_flow_id, VAR);

    //Flow id hash -> flow data
    //Note: Tofino can only store at most 2*32 bits in a single register, so we use multiple registers
    HASH_REGISTER(TimestampUint_t, flow_data_timestamp_first_register);
    HASH_REGISTER(TimestampUint_t, flow_data_timestamp_previous_register);
    HASH_REGISTER(protocol_port_t, flow_data_port_client_register);
    HASH_REGISTER(label_t, flow_data_label_register);

    //Flow id hash -> features
    //Note: Tofino can only store at most 2*32 bits in a single register, so we use multiple registers
    HASH_REGISTER(feature_iat_t, feature_iat_min_register);
    HASH_REGISTER(feature_iat_t, feature_iat_max_register);
    HASH_REGISTER(feature_iat_t, feature_iat_avg_register);
    HASH_REGISTER(feature_length_t, feature_length_min_register);
    HASH_REGISTER(feature_length_t, feature_length_max_register);
    HASH_REGISTER(feature_length_t, feature_length_avg_register);
    HASH_REGISTER(feature_length_sum_t, feature_length_sum_register);
    HASH_REGISTER(feature_count_t, feature_count_register);
    HASH_REGISTER(feature_count_tcp_t, feature_count_tcp_syn_register);
    HASH_REGISTER(feature_count_tcp_t, feature_count_tcp_ack_register);
    HASH_REGISTER(feature_count_tcp_t, feature_count_tcp_psh_register);
    HASH_REGISTER(feature_count_tcp_t, feature_count_tcp_fin_register);
    HASH_REGISTER(feature_count_tcp_t, feature_count_tcp_rst_register);
    HASH_REGISTER(feature_count_tcp_t, feature_count_tcp_ece_register);

    ///////////////
    // INFERENCE //
    ///////////////

    //Register written by the control plane that specifies which DTs of the RF are stored on this specific switch.
    //  A switch has enough resources to store N DTs, but the model might consist of more than N DTs. Therefore the
    //  model is distributed across multiple switches. Each switch must know which DTs it stores, because each DT
    //  must only be executed only once per packet.
    Register<dt_bitflag_t, dt_id_t>(DT_PER_SWITCH_COUNT) dt_num_to_dt_id_bitflag_register;

    //Determining which RF to use
    action set_rf_id(rf_id_t rf_id) {
        hdr.inference.rf_id = rf_id;
    }
    table rf_id_table {
        //key = { user_meta.features.count: range; } //Range matching isn't supported by p4c-psa
        key = { user_meta.features.count: exact; }
        actions = { set_rf_id; }
        default_action = set_rf_id(RF_ID_DONT_CLASSIFY);
        size = MAX_CLASSIFIABLE_FLOW_LENGTH;
    }

    //Computes which node in the decision tree to go to next
    action inference_process_node(node_id_t next_node_id, bit<8> next_feature, bit<64> next_threshold) {
        bit<64> value;
        if      (next_feature == 0) { value = (bit<64>) user_meta.features.count; }
        else if (next_feature == 1) { value = (bit<64>) user_meta.features.iat_min; }
        else if (next_feature == 2) { value = (bit<64>) user_meta.features.iat_max; }
        else if (next_feature == 3) { value = (bit<64>) user_meta.features.iat_avg; }
        else if (next_feature == 4) { value = (bit<64>) user_meta.features.length_min; }
        else if (next_feature == 5) { value = (bit<64>) user_meta.features.length_max; }
        else if (next_feature == 6) { value = (bit<64>) user_meta.features.length_avg; }
        else if (next_feature == 7) { value = (bit<64>) user_meta.features.length_sum; }
        else if (next_feature == 8) { value = (bit<64>) user_meta.features.count_tcp_syn; }
        else if (next_feature == 9) { value = (bit<64>) user_meta.features.count_tcp_ack; }
        else if (next_feature == 10) { value = (bit<64>) user_meta.features.count_tcp_psh; }
        else if (next_feature == 11) { value = (bit<64>) user_meta.features.count_tcp_fin; }
        else if (next_feature == 12) { value = (bit<64>) user_meta.features.count_tcp_rst; }
        else if (next_feature == 13) { value = (bit<64>) user_meta.features.count_tcp_ece; }
        else if (next_feature == 14) { value = (bit<64>) user_meta.features.duration; }
        else if (next_feature == 15) { value = (bit<64>) user_meta.features.port_client; }
        else if (next_feature == 16) { value = (bit<64>) user_meta.features.port_server; }
        else if (next_feature == 17) { value = (bit<64>) user_meta.features.length_current; }
        else { value = 0; } //This case shouldn't happen

        user_meta.dt.node_id = next_node_id;
        user_meta.dt.threshold_passed = value > next_threshold ? (bit<1>) 1 : 0;
    }

    //Sets the label and the certainty based on the node we ended up at in the decision tree
    action inference_process_node_final(label_t label, certainty_t certainty) {
        certainty_sum_t c = (certainty_sum_t) certainty;
        if      (label == 1) { hdr.inference.certainty_sum_label_1 = hdr.inference.certainty_sum_label_1 + c; }
        else if (label == 2) { hdr.inference.certainty_sum_label_2 = hdr.inference.certainty_sum_label_2 + c; }
        #if VALID_LABEL_COUNT != 2
            #error "Source code doesn't match configuration; please check this error's source location."
        #endif
        //Make sure the subsequent depths aren't executed (by causing the match-action tables to miss)
        user_meta.dt.rf_id = RF_ID_DONT_CLASSIFY; //This gets reset before each DT execution
    }

//Creates a match-action table for the specified decision tree's specified depth
#define DT_DEPTH_TABLE(NUM,DEPTH) \
    table dt_ ## NUM ## _depth_ ## DEPTH ## _table { \
        key = { user_meta.dt.rf_id: exact; user_meta.dt.node_id: exact; user_meta.dt.threshold_passed: exact; } \
        actions = { inference_process_node; inference_process_node_final; } \
        /* size: 2^depth entries for each RF: MAX_RF_COUNT existing, x2 for atomic RF replacement support */ \
        size = (MAX_RF_COUNT * 2) * (1 << DEPTH); }

//Creates all the depths for the specified decision tree
#define DT_CREATE(NUM) DT_DEPTH_TABLE(NUM,0) \
    DT_DEPTH_TABLE(NUM,1) DT_DEPTH_TABLE(NUM,2) DT_DEPTH_TABLE(NUM,3)  \
    DT_DEPTH_TABLE(NUM,4) DT_DEPTH_TABLE(NUM,5) DT_DEPTH_TABLE(NUM,6) \
    DT_DEPTH_TABLE(NUM,7)
#if MAX_DT_DEPTH != 7
    #error "Source code doesn't match configuration; please check this error's source location."
#endif

//Executes the specified decision tree (if it hasn't bee applied yet) by traversing (applying) its depths in order
#define DT_EXECUTE_IF_NECESSARY(NUM) \
    if (true) { /* Open a new scope so that we can declare new local variables without issues */ \
    dt_id_t num_as_var = NUM; /* Required because of some compiler bug */ \
    dt_bitflag_t dt_id_bitflag = dt_num_to_dt_id_bitflag_register.read(num_as_var); \
    if (hdr.inference.executed_dt_bitflag & dt_id_bitflag == 0) { \
        hdr.inference.executed_dt_bitflag = hdr.inference.executed_dt_bitflag | dt_id_bitflag; \
        hdr.inference.executed_dt_count = hdr.inference.executed_dt_count + 1; \
        user_meta.dt.rf_id = hdr.inference.rf_id; user_meta.dt.node_id = 0; user_meta.dt.threshold_passed = 0; \
        dt_ ## NUM ## _depth_0_table.apply(); dt_ ## NUM ## _depth_1_table.apply(); \
        dt_ ## NUM ## _depth_2_table.apply(); dt_ ## NUM ## _depth_3_table.apply(); \
        dt_ ## NUM ## _depth_4_table.apply(); dt_ ## NUM ## _depth_5_table.apply(); \
        dt_ ## NUM ## _depth_6_table.apply(); dt_ ## NUM ## _depth_7_table.apply(); } }
#if MAX_DT_DEPTH != 7
    #error "Source code doesn't match configuration; please check this error's source location."
#endif

    //Create decision trees
    DT_CREATE(0) DT_CREATE(1)
    #if DT_PER_SWITCH_COUNT != 2
        #error "Source code doesn't match configuration; please check this error's source location."
    #endif

//Update the RF verdict based on a label's certainty
#define RF_VERDICT_PROCESS_LABEL(LABEL) \
    if (user_meta.rf.verdict_certainty_sum < hdr.inference.certainty_sum_label_ ## LABEL) { \
        user_meta.rf.verdict_certainty_sum = hdr.inference.certainty_sum_label_ ## LABEL; \
        user_meta.rf.verdict_label = LABEL; }

    //Register written by the control plane used to determine whether the RF's verdict can be trusted
    Register<certainty_sum_t, bit<1>>(1, 0) rf_certainty_sum_threshold_per_executed_dt_register;

    ////////////////////
    // LABEL HANDLING //
    ////////////////////

    //Saves the values necessary for L3 forwarding to temporary meta struct. This is necessary to allow executing
    //  L3 forwarding from within an action. The packet is dropped if no matching entry is found.
    action l3_forward_set(PortId_t egress_port, macAddr_t dst_mac, bool leaves_network) {
        user_meta.tmp_l3_forward.drop = 0;
        user_meta.tmp_l3_forward.egress_port = egress_port;
        user_meta.tmp_l3_forward.dst_mac = dst_mac;
        user_meta.tmp_l3_forward.leaves_network = leaves_network;
    }
    action l3_forward_drop() {
        user_meta.tmp_l3_forward.drop = 1;
    }
    table l3_forward_table {
        key = { hdr.ipv4.dstAddr: lpm; }
        actions = { l3_forward_set; l3_forward_drop; }
        size = L3_TABLE_SIZE;
        default_action = l3_forward_drop();
    }

    //Action to execute when the packet leaves the internal network (e.g. when it is forwarded to a host)
    action handle_leaves_network() {
        //Remove header(s) which are only used within the internal network, e.g. for inter-switch communication
        hdr.ethernet.etherType = hdr.inference.etherType;
        hdr.inference.setInvalid();
    }

    //Actions that can be executed based on the flow label
    action flow_action_drop() {
        ingress_drop(ostd);
    }
    action flow_action_l3_forward() {
        //Update the TTL
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
        if (hdr.ipv4.ttl == 0 || user_meta.tmp_l3_forward.drop == 1) {
            ingress_drop(ostd);
        } else {
            //Recompute the checksum because the TTL changed
            hdr.ipv4.hdrChecksum = hash_csum16.get_hash({hdr.ipv4.version, hdr.ipv4.ihl, hdr.ipv4.dscp, hdr.ipv4.ecn,
                    hdr.ipv4.totalLen, hdr.ipv4.identification, hdr.ipv4.flags, hdr.ipv4.fragOffset, hdr.ipv4.ttl,
                    hdr.ipv4.protocol, hdr.ipv4.srcAddr, hdr.ipv4.dstAddr});

            //Set egress port and destination MAC
            send_to_port(ostd, user_meta.tmp_l3_forward.egress_port);
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = user_meta.tmp_l3_forward.dst_mac;

            if (user_meta.tmp_l3_forward.leaves_network) {
                handle_leaves_network();
            }
        }
    }
    action flow_action_port_forward_within_network(PortId_t egress_port, macAddr_t dst_mac) {
        send_to_port(ostd, egress_port);
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dst_mac;
    }
    action flow_action_port_forward_outside_network(PortId_t egress_port, macAddr_t dst_mac) {
        flow_action_port_forward_within_network(egress_port, dst_mac);
        handle_leaves_network();
    }

    //Executes an action based on the flow's label
    table flow_action_table {
        key = { user_meta.flow_data.label: exact; }
        actions = { flow_action_l3_forward; flow_action_drop;
                    flow_action_port_forward_outside_network; flow_action_port_forward_within_network; }
        size = VALID_LABEL_COUNT + 1;
        default_action = flow_action_l3_forward();
    }

    ///////////////////////////
    // REPORTING, MONITORING //
    ///////////////////////////

    //Register written by the control plane that specifies which port is the CPU port
    //  Note: PSA_PORT_CPU, despite being in the specification, does not work with eBPF-PSA
    //  Note: this register is not in the egress pipeline due to some obscure bug: eBPF loading fails in that case
    Register<PortId_t, bit<1>>(1) cpu_port_register;

    //Register written by the control plane that specifies below what mutated hash flow id values the flows get reported
    //  value of n ==> n/(2^32) of the flows are reported
    //  Exception: if n == 0, no flows are reported
    Register<hashed_flow_id_t, bit<1>>(1, 1) reported_flow_max_hash_register;

    //Value used to modify the flow id to mitigate clients being able to predict which flows are going to be reported.
    //  TODO The value should be randomized on switch startup.
    const hashed_flow_id_t reporting_flow_id_mutator = 0x1234;

    ///////////
    // APPLY //
    ///////////

    apply { @atomic {
        bit<1> const_zero = 0; //This is a workaround for a bug in the compiler

        //Drop packets we can't process
        if (!hdr.ipv4.isValid()) {
            ingress_drop(ostd);
            return;
        }

        //Get the TCP/UDP ports
        protocol_port_t port_src = hdr.tcp.isValid() ? hdr.tcp.srcPort : (hdr.udp.isValid() ? hdr.udp.srcPort : 0);
        protocol_port_t port_dst = hdr.tcp.isValid() ? hdr.tcp.dstPort : (hdr.udp.isValid() ? hdr.udp.dstPort : 0);

        //Calculate the flow ID
        //Treat forward and backward direction (e.g. TCP payload and ACK) as the same flow
        user_meta.flow_id = {
            MIN(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr),
            MAX(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr),
            hdr.ipv4.protocol,
            port_src,
            port_dst
        };
        //Fix (flip) the port numbers if the lower IP is the source IP (because the IPs have already been flipped)
        if (user_meta.flow_id.ip_lower == hdr.ipv4.dstAddr) {
            user_meta.flow_id.port_at_lower = port_dst;
            user_meta.flow_id.port_at_upper = port_src;
        }
        //The compiler doesn't allow us to hash the flow id directly
        user_meta.hashed_flow_id = (hashed_flow_id_t) hash_crc32.get_hash(0, {user_meta.flow_id.ip_lower,
                user_meta.flow_id.ip_upper, user_meta.flow_id.protocol, user_meta.flow_id.port_at_lower,
                user_meta.flow_id.port_at_upper}, (bit<32>) (1 << HASHED_FLOW_ID_WIDTH));

        ////////////////////////////
        // HASH-BASED PERSISTENCE //
        ////////////////////////////

        TimestampUint_t timestamp = (TimestampUint_t) istd.ingress_timestamp >> 10; //nanoseconds to microseconds
        HASH_READ(flow_data_timestamp_previous_register, user_meta.flow_data.timestamp_previous);
        HASH_WRITE(flow_data_timestamp_previous_register, timestamp);
        bool reset_flow_data = timestamp > user_meta.flow_data.timestamp_previous + FLOW_TIMEOUT_THRESHOLD;

        //Flow data
        if (reset_flow_data) {
            HASH_SET_WRITE(flow_data_timestamp_first_register, user_meta.flow_data.timestamp_first, timestamp);
            user_meta.flow_data.iat_latest = 0;
            HASH_SET_WRITE(flow_data_port_client_register, user_meta.flow_data.port_client, port_src);
        } else {
           HASH_READ(flow_data_timestamp_first_register, user_meta.flow_data.timestamp_first);
           user_meta.flow_data.iat_latest = timestamp - user_meta.flow_data.timestamp_previous;
           HASH_READ(flow_data_port_client_register, user_meta.flow_data.port_client);
        }
        user_meta.flow_data.port_server = port_src == user_meta.flow_data.port_client ? port_dst : port_src; //Save memory by only persisting one of the two ports

        //Stateless, computed features
        user_meta.features.port_client = user_meta.flow_data.port_client;
        user_meta.features.port_server = user_meta.flow_data.port_server;
        user_meta.features.length_current = hdr.ipv4.totalLen;
        user_meta.features.duration = (feature_duration_t) (timestamp - user_meta.flow_data.timestamp_first);

        //Regular features
        if (reset_flow_data) {
            HASH_SET_WRITE(feature_count_register, user_meta.features.count, 1);
            HASH_SET_WRITE(feature_iat_min_register, user_meta.features.iat_min, FEATURE_IAT_MAX);
            HASH_SET_WRITE(feature_iat_max_register, user_meta.features.iat_max, (feature_iat_t) user_meta.flow_data.iat_latest);
            HASH_SET_WRITE(feature_iat_avg_register, user_meta.features.iat_avg, (feature_iat_t) user_meta.flow_data.iat_latest);
            HASH_SET_WRITE(feature_length_min_register, user_meta.features.length_min, user_meta.features.length_current);
            HASH_SET_WRITE(feature_length_max_register, user_meta.features.length_max, user_meta.features.length_current);
            HASH_SET_WRITE(feature_length_avg_register, user_meta.features.length_avg, user_meta.features.length_current);
            HASH_SET_WRITE(feature_length_sum_register, user_meta.features.length_sum, (feature_length_sum_t) user_meta.features.length_current);
            HASH_SET_WRITE(feature_count_tcp_syn_register, user_meta.features.count_tcp_syn, (feature_count_tcp_t) (hdr.tcp.isValid() ? hdr.tcp.syn : 0));
            HASH_SET_WRITE(feature_count_tcp_ack_register, user_meta.features.count_tcp_ack, (feature_count_tcp_t) (hdr.tcp.isValid() ? hdr.tcp.ack : 0));
            HASH_SET_WRITE(feature_count_tcp_psh_register, user_meta.features.count_tcp_psh, (feature_count_tcp_t) (hdr.tcp.isValid() ? hdr.tcp.psh : 0));
            HASH_SET_WRITE(feature_count_tcp_fin_register, user_meta.features.count_tcp_fin, (feature_count_tcp_t) (hdr.tcp.isValid() ? hdr.tcp.fin : 0));
            HASH_SET_WRITE(feature_count_tcp_rst_register, user_meta.features.count_tcp_rst, (feature_count_tcp_t) (hdr.tcp.isValid() ? hdr.tcp.rst : 0));
            HASH_SET_WRITE(feature_count_tcp_ece_register, user_meta.features.count_tcp_ece, (feature_count_tcp_t) (hdr.tcp.isValid() ? hdr.tcp.ece : 0));
        } else {
            //Do not let the counter overflow, but still allow us to detect when the max flow length has been exceeded
            HASH_READ_UPDATE_WRITE(feature_count_register, user_meta.features.count, 1 + MIN(user_meta.features.count, MAX_CLASSIFIABLE_FLOW_LENGTH));
            HASH_READ_UPDATE_WRITE(feature_iat_min_register, user_meta.features.iat_min, MIN(user_meta.features.iat_min, (feature_iat_t) user_meta.flow_data.iat_latest));
            HASH_READ_UPDATE_WRITE(feature_iat_max_register, user_meta.features.iat_max, MAX(user_meta.features.iat_max, (feature_iat_t) user_meta.flow_data.iat_latest));
            HASH_READ_AVERAGE_WRITE(feature_iat_avg_register, user_meta.features.iat_avg, (feature_iat_t) user_meta.flow_data.iat_latest, FEATURE_IAT_WIDTH);
            HASH_READ_UPDATE_WRITE(feature_length_min_register, user_meta.features.length_min, MIN(user_meta.features.length_min, user_meta.features.length_current));
            HASH_READ_UPDATE_WRITE(feature_length_max_register, user_meta.features.length_max, MAX(user_meta.features.length_max, user_meta.features.length_current));
            HASH_READ_AVERAGE_WRITE(feature_length_avg_register, user_meta.features.length_avg, user_meta.features.length_current, FEATURE_LENGTH_WIDTH);
            HASH_READ_SUM_WRITE(feature_length_sum_register, user_meta.features.length_sum, (feature_length_sum_t) user_meta.features.length_current, FEATURE_LENGTH_SUM_MAX);
            HASH_READ_UPDATE_WRITE(feature_count_tcp_syn_register, user_meta.features.count_tcp_syn, user_meta.features.count_tcp_syn + (feature_count_tcp_t) (hdr.tcp.isValid() ? hdr.tcp.syn : 0));
            HASH_READ_UPDATE_WRITE(feature_count_tcp_ack_register, user_meta.features.count_tcp_ack, user_meta.features.count_tcp_ack + (feature_count_tcp_t) (hdr.tcp.isValid() ? hdr.tcp.ack : 0));
            HASH_READ_UPDATE_WRITE(feature_count_tcp_psh_register, user_meta.features.count_tcp_psh, user_meta.features.count_tcp_psh + (feature_count_tcp_t) (hdr.tcp.isValid() ? hdr.tcp.psh : 0));
            HASH_READ_UPDATE_WRITE(feature_count_tcp_fin_register, user_meta.features.count_tcp_fin, user_meta.features.count_tcp_fin + (feature_count_tcp_t) (hdr.tcp.isValid() ? hdr.tcp.fin : 0));
            HASH_READ_UPDATE_WRITE(feature_count_tcp_rst_register, user_meta.features.count_tcp_rst, user_meta.features.count_tcp_rst + (feature_count_tcp_t) (hdr.tcp.isValid() ? hdr.tcp.rst : 0));
            HASH_READ_UPDATE_WRITE(feature_count_tcp_ece_register, user_meta.features.count_tcp_ece, user_meta.features.count_tcp_ece + (feature_count_tcp_t) (hdr.tcp.isValid() ? hdr.tcp.ece : 0));
        }

        //Set features to 0 that are not supported by Tofino
        user_meta.features.iat_min = 0;
        user_meta.features.iat_max = 0;
        user_meta.features.iat_avg = 0;
        user_meta.features.length_avg = 0;
        user_meta.features.duration = 0;

        ///////////////
        // INFERENCE //
        ///////////////

        //Initialize the inference sub-results
        if (!hdr.inference.isValid()) {
            hdr.inference.setValid();
            hdr.inference.etherType = hdr.ethernet.etherType;
            hdr.ethernet.etherType = ETHER_TYPE_INFERENCE;

            rf_id_table.apply();  //Sets hdr.inference.rf_id
            hdr.inference.executed_dt_count = 0;
            hdr.inference.executed_dt_bitflag = 0;

            hdr.inference.certainty_sum_label_1 = 0; hdr.inference.certainty_sum_label_2 = 0;
            #if VALID_LABEL_COUNT != 2
                #error "Source code doesn't match configuration; please check this error's source location."
            #endif
        }

        //Apply each decision tree in the random forest (if an RF is available)
        if (hdr.inference.rf_id != RF_ID_DONT_CLASSIFY) {
            //This if statement is necessary to make sure executed_dt_count is not increment if there is no RF set
            DT_EXECUTE_IF_NECESSARY(0); DT_EXECUTE_IF_NECESSARY(1);
            #if DT_PER_SWITCH_COUNT != 2
                #error "Source code doesn't match configuration; please check this error's source location."
            #endif
        }

        //Try to determine the label if enough DTs have been executed
        //Any switch on the packet's path can calculate the label and act on it. For example, the switch can drop
        //  the packet and reduce load on subsequent switches. Another approach (not implemented here) is to only
        //  add the following logic to specific "edge" switches, saving resources on the other switches.
        user_meta.rf.verdict_label = LABEL_NOT_SET;
        user_meta.rf.verdict_certainty_sum = 0;
        if (hdr.inference.executed_dt_count >= DT_COUNT_REQUIRED_TO_SET_LABEL) {

            //Find the label with the highest certainty sum
            RF_VERDICT_PROCESS_LABEL(1) RF_VERDICT_PROCESS_LABEL(2)
            #if VALID_LABEL_COUNT != 2
                #error "Source code doesn't match configuration; please check this error's source location."
            #endif

            //Calculate the verdict of the random forest
            //(The majority of the calculation is done during the application of the individual decision trees)
            certainty_sum_t certainty_threshold = rf_certainty_sum_threshold_per_executed_dt_register.read(const_zero)
                     * (certainty_sum_t) hdr.inference.executed_dt_count;
            label_t new_label = user_meta.rf.verdict_certainty_sum > certainty_threshold
                    ? user_meta.rf.verdict_label : LABEL_NOT_SET;

            //Don't use the verdict if the features might have overflowed
            if (user_meta.features.count > MAX_CLASSIFIABLE_FLOW_LENGTH) {
                new_label = LABEL_NOT_SET;
            }

            //Save the new flow label: overwrite previous value if the previous value is LABEL_NOT_SET
            if (reset_flow_data) {
                HASH_SET_WRITE(flow_data_label_register, user_meta.flow_data.label, new_label);
            } else {
                HASH_READ(flow_data_label_register, user_meta.flow_data.label);
                if (user_meta.flow_data.label == LABEL_NOT_SET && new_label != LABEL_NOT_SET) {
                    HASH_SET_WRITE(flow_data_label_register, user_meta.flow_data.label, new_label);
                }
            }
        }

        ////////////////////
        // LABEL HANDLING //
        ////////////////////

        l3_forward_table.apply();
        dt_count_t executed_dt_count = hdr.inference.executed_dt_count;
        flow_action_table.apply(); //uses user_meta.flow_data.label and invalidates hdr.inference

        ///////////////////////////
        // REPORTING, MONITORING //
        ///////////////////////////

        user_meta.cpu_port = cpu_port_register.read(const_zero);

        hashed_flow_id_t mutated_flow_id_hash = user_meta.hashed_flow_id ^ reporting_flow_id_mutator;
        hashed_flow_id_t reported_flow_max_hash = reported_flow_max_hash_register.read(const_zero);
        // If the max hash is 0, that means that reporting is explicitly disabled
        if (reported_flow_max_hash != 0 && mutated_flow_id_hash <= reported_flow_max_hash) {
            //Packet cloning can't be used, see: https://github.com/p4lang/p4c/issues/4958

            //For some reason the = { xyz = abc; } syntax doesn't work: the header becomes invalid
            hdr.reporting.setValid();
            //flow_id_t flow_id:
            hdr.reporting.flow_id_ip_lower = user_meta.flow_id.ip_lower;
            hdr.reporting.flow_id_ip_upper = user_meta.flow_id.ip_upper;
            hdr.reporting.flow_id_protocol = user_meta.flow_id.protocol;
            hdr.reporting.flow_id_port_at_lower = user_meta.flow_id.port_at_lower;
            hdr.reporting.flow_id_port_at_upper = user_meta.flow_id.port_at_upper;
            //features_t features:
            hdr.reporting.count = user_meta.features.count;
            hdr.reporting.iat_min = user_meta.features.iat_min;
            hdr.reporting.iat_max = user_meta.features.iat_max;
            hdr.reporting.iat_avg = user_meta.features.iat_avg;
            hdr.reporting.length_min = user_meta.features.length_min;
            hdr.reporting.length_max = user_meta.features.length_max;
            hdr.reporting.length_avg = user_meta.features.length_avg;
            hdr.reporting.length_sum = user_meta.features.length_sum;
            hdr.reporting.count_tcp_syn = user_meta.features.count_tcp_syn;
            hdr.reporting.count_tcp_ack = user_meta.features.count_tcp_ack;
            hdr.reporting.count_tcp_psh = user_meta.features.count_tcp_psh;
            hdr.reporting.count_tcp_fin = user_meta.features.count_tcp_fin;
            hdr.reporting.count_tcp_rst = user_meta.features.count_tcp_rst;
            hdr.reporting.count_tcp_ece = user_meta.features.count_tcp_ece;
            hdr.reporting.duration = user_meta.features.duration;
            hdr.reporting.port_client = user_meta.features.port_client;
            hdr.reporting.port_server = user_meta.features.port_server;
            hdr.reporting.length_current = user_meta.features.length_current;
            //label_t accepted_label:
            hdr.reporting.accepted_label = user_meta.flow_data.label;
            //label_t latest_label:
            hdr.reporting.latest_label = user_meta.rf.verdict_label;
            //certainty_sum_t latest_label_certainty_sum:
            hdr.reporting.latest_label_certainty_sum = user_meta.rf.verdict_certainty_sum;
            //dt_count_t latest_label_dt_count:
            hdr.reporting.latest_label_dt_count = executed_dt_count;

            if (ostd.drop) {
                //Forward the packet just to the CPU
                send_to_port(ostd, PSA_PORT_CPU);
            } else {
                //Send the packet both to the CPU and to its original destination
                multicast(ostd, (MulticastGroup_t) (bit<32>) ostd.egress_port);
            }
        }
    } /* end @atomic */ }
}
