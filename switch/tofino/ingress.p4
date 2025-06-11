control MyIngress(inout headers_t hdr,
                inout ingress_user_meta_t user_meta,
                in ingress_intrinsic_metadata_t ig_intr_md,
                in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
                inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
                inout ingress_intrinsic_metadata_for_tm_t ig_tm_md) {

    Hash<bit<32>>(HashAlgorithm_t.CRC32) hash_crc32;

    ////////////////////////////////////
    // FLOW ID HASH BASED PERSISTENCE //
    ////////////////////////////////////

//Creates a register (with the specified initial value) and a register action that executes the following:
//     reg_val := REG.read(hashed_flow_id) ; reg_val := FUN ; REG.write(hashed_flow_id, reg_val) ; return reg_val
//  (FUN may be an expression referencing reg_val)
#define HASH_UPDATE_ACTION(TYPE, REG, INITIAL_VALUE, FUN) \
        Register<TYPE, hashed_flow_id_t>(1 << HASHED_FLOW_ID_WIDTH, INITIAL_VALUE) REG; \
        RegisterAction<TYPE, hashed_flow_id_t, TYPE>(REG) REG ## _action = { \
            void apply(inout TYPE reg_val, out TYPE return_value) { \
                if (user_meta.reset_flow_data == 1) { reg_val = INITIAL_VALUE; } \
                reg_val = FUN; return_value = reg_val; \
            } \
        };

//Creates a register (with the specified initial value) and a register action that increments by 1 if the specified flag is set in the TCP header.
#define HASH_INCREMENT_TCP_FLAG_ACTION(REG, FLAG) \
        Register<feature_count_tcp_t, hashed_flow_id_t>(1 << HASHED_FLOW_ID_WIDTH, 0) REG; \
        RegisterAction<feature_count_tcp_t, hashed_flow_id_t, feature_count_tcp_t>(REG) REG ## _action = { \
            void apply(inout feature_count_tcp_t reg_val, out feature_count_tcp_t return_value) { \
                if (hdr.tcp.isValid()) { reg_val = reg_val + (feature_count_tcp_t) FLAG; } \
                return_value = reg_val; \
            } \
        }; \
        /* I wasn't able to implement the updating & resetting functions into the same register action. */ \
        RegisterAction<feature_count_tcp_t, hashed_flow_id_t, feature_count_tcp_t>(REG) REG ## _reset_action = { \
            void apply(inout feature_count_tcp_t reg_val, out feature_count_tcp_t return_value) { \
                if (hdr.tcp.isValid()) { reg_val = (feature_count_tcp_t) FLAG; } \
                else { reg_val = 0; } \
                return_value = reg_val; \
            } \
        };
//Executes a register action created by a HASH_*_ACTION macro.
#define HASH_EXECUTE_ACTION(REG) REG ## _action.execute(user_meta.hashed_flow_id)
#define HASH_EXECUTE_RESET_ACTION(REG) REG ## _reset_action.execute(user_meta.hashed_flow_id)

    Register<timestamp_t, hashed_flow_id_t>(1 << HASHED_FLOW_ID_WIDTH, 0) flow_data_timeout_register;
    RegisterAction<timestamp_t, hashed_flow_id_t, timestamp_t>(flow_data_timeout_register) flow_data_timeout_register_action = {
        void apply(inout timestamp_t reg_val, out timestamp_t return_value) {
            timestamp_t current_time = (timestamp_t) (ig_intr_md.ingress_mac_tstamp >> TIMESTAMP_SHIFT_AMOUNT);
            // What happens: return_value = current_time |-| (previous_time |+| FLOW_TIMEOUT_THRESHOLD);
            return_value = current_time |-| reg_val;  //0 if the flow hasn't timed out yet
            reg_val = current_time |+| FLOW_TIMEOUT_THRESHOLD;
            //Our handling of overflows/underflows is not perfect: we don't time flows out when an overflow happens
        }
    };

    Register<protocol_port_t, hashed_flow_id_t>(1 << HASHED_FLOW_ID_WIDTH, 255) flow_data_port_client_register;
    RegisterAction<protocol_port_t, hashed_flow_id_t, protocol_port_t>(flow_data_port_client_register) flow_data_port_client_register_action = {
        void apply(inout protocol_port_t reg_val, out protocol_port_t return_value) {
            if (user_meta.reset_flow_data == 1 || reg_val == 255) { reg_val = user_meta.port_src; }
            return_value = reg_val;
        }
    };

    Register<label_t, hashed_flow_id_t>(1 << HASHED_FLOW_ID_WIDTH, 0) flow_data_label_register;
    RegisterAction<label_t, hashed_flow_id_t, label_t>(flow_data_label_register) flow_data_label_register_action = {
        void apply(inout label_t reg_val, out label_t return_value) {
            if (user_meta.reset_flow_data == 1 || reg_val == LABEL_NOT_SET) { reg_val = user_meta.rf.verdict_label; }
            return_value = reg_val;
        }
    };

    //Do not let the counter overflow, but still allow us to detect when the max flow length has been exceeded
    Register<feature_count_t, hashed_flow_id_t>(1 << HASHED_FLOW_ID_WIDTH, 0) feature_count_register;
    RegisterAction<feature_count_t, hashed_flow_id_t, feature_count_t>(feature_count_register) feature_count_register_action = {
        void apply(inout feature_count_t reg_val, out feature_count_t return_value) {
            if (user_meta.reset_flow_data == 1) { reg_val = 1; }
            //Goal: don't let the counter overflow (we could also achieve that using saturation arithmetic)
            else if (reg_val <= MAX_CLASSIFIABLE_FLOW_LENGTH) { reg_val = reg_val + 1; }
            return_value = reg_val;
        }
    };

    //Some not used features are disabled to save resources
    //HASH_UPDATE_ACTION(feature_length_t, feature_length_min_register, FEATURE_LENGTH_MAX, min(reg_val, user_meta.features.length_current))
    HASH_UPDATE_ACTION(feature_length_t, feature_length_max_register, 0, max(reg_val, user_meta.features.length_current))
    HASH_UPDATE_ACTION(feature_length_sum_t, feature_length_sum_register, 0, reg_val |+| (feature_length_sum_t) user_meta.features.length_current)
    HASH_INCREMENT_TCP_FLAG_ACTION(feature_count_tcp_syn_register, hdr.tcp.syn)
    HASH_INCREMENT_TCP_FLAG_ACTION(feature_count_tcp_ack_register, hdr.tcp.ack)
    //HASH_INCREMENT_TCP_FLAG_ACTION(feature_count_tcp_psh_register, hdr.tcp.psh)
    //HASH_INCREMENT_TCP_FLAG_ACTION(feature_count_tcp_fin_register, hdr.tcp.fin)
    HASH_INCREMENT_TCP_FLAG_ACTION(feature_count_tcp_rst_register, hdr.tcp.rst)
    //HASH_INCREMENT_TCP_FLAG_ACTION(feature_count_tcp_ece_register, hdr.tcp.ece)

    ///////////////
    // INFERENCE //
    ///////////////

    //Table used to determine which DTs to execute on this switch (mapping from DT IDs to DT NUMs)
    //  and to update the executed DT ID bitflag.
    action dt_id_bitflag_table_action(dt_bitflag_t updated_executed_dt_bitflag, dt_count_t updated_executed_dt_count,
            bool dt_execute_0, bool dt_execute_1) {
        hdr.inference.executed_dt_bitflag = updated_executed_dt_bitflag;
        hdr.inference.executed_dt_count = updated_executed_dt_count;

        user_meta.rf.dt_execute_0 = dt_execute_0; user_meta.rf.dt_execute_1 = dt_execute_1;
        #if DT_PER_SWITCH_COUNT != 2
            error "Source code doesn't match configuration; please check this error's source location."
        #endif
    }
    table dt_id_bitflag_table {
        key = { hdr.inference.executed_dt_bitflag: exact; }
        actions = { dt_id_bitflag_table_action; }
        size = 1 << DT_PER_RF_COUNT;
        //TODO we should add one more key, the RF ID, if not the same DT ID is placed into the same DT slot every time
        //TODO size scales poorly with DT count, but could be optimized using: 1) ternary matches 2) default action
    }

    //Determining which RF to use
    action set_rf_id(rf_id_t rf_id) {
        hdr.inference.rf_id = rf_id;
    }
    table rf_id_table {
        key = { user_meta.features.count: exact; }
        actions = { set_rf_id; }
        default_action = set_rf_id(RF_ID_DONT_CLASSIFY);
        size = MAX_CLASSIFIABLE_FLOW_LENGTH;
    }

//Creates a decision tree table with the specified numerical identifier
    action dt_label_1_action(certainty_t certainty) {
        hdr.inference.certainty_sum_label_1 = hdr.inference.certainty_sum_label_1 + (certainty_sum_t) certainty;
    }
    action dt_label_2_action(certainty_t certainty) {
        hdr.inference.certainty_sum_label_2 = hdr.inference.certainty_sum_label_2 + (certainty_sum_t) certainty;
    }
#define DT_CREATE(NUM) \
    table dt_ ## NUM ## _table { \
        key = { \
            hdr.inference.rf_id: exact; \
            /* Only a limited number of keys are supported by Tofino */ \
            /* Keys must be in the same order as the feature declarations in the control plane */ \
            user_meta.features.length_max: range; user_meta.features.length_sum: range; \
            user_meta.features.count_tcp_syn: range; user_meta.features.count_tcp_ack: range; \
            user_meta.features.count_tcp_rst: range; user_meta.features.port_client: range; \
            user_meta.features.port_server: range; user_meta.features.length_current: range; \
        } \
        actions = { dt_label_1_action; dt_label_2_action; } \
        size = 2 * (1 << MAX_DT_DEPTH) * MAX_RF_COUNT; /* 1 active + 1 inactive entry per leaf per RF */ \
    }
    #if VALID_LABEL_COUNT != 2
        error "Source code doesn't match configuration; please check this error's source location."
    #endif

    //Create decision trees
    DT_CREATE(0) DT_CREATE(1)
    #if DT_PER_SWITCH_COUNT != 2
        error "Source code doesn't match configuration; please check this error's source location."
    #endif

    //A table that fins the label with the highest certainty sum, also taking the certainty threshold into account
    action certainties_to_verdict_table_action(label_t label) {
        user_meta.rf.verdict_label = label;
        user_meta.rf.verdict_certainty_sum = max(hdr.inference.certainty_sum_label_1, hdr.inference.certainty_sum_label_2);
    }
    table certainties_to_verdict_table {
        key = { hdr.inference.certainty_sum_label_1: range; hdr.inference.certainty_sum_label_2: range; }
        actions = { certainties_to_verdict_table_action; }
        default_action = certainties_to_verdict_table_action(LABEL_NOT_SET);
        size = 2;
    }
    #if VALID_LABEL_COUNT != 2
        error "Source code doesn't match configuration; please check this error's source location."
    #endif

    ////////////////////
    // LABEL HANDLING //
    ////////////////////

    //Drop the packet
    action flow_action_drop() {
        ig_dprsr_md.drop_ctl = 1;
    }

    //Forward the packet to the specified destination (e.g. a switch), which is still inside the internal network
    action flow_action_port_forward_within_network(WidePortId_t egress_port, macAddr_t dst_mac) {
        ig_tm_md.ucast_egress_port = (PortId_t) egress_port;
        hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
        hdr.ethernet.dstAddr = dst_mac;
    }

    //Forward the packet to the specified destination (e.g. a host), which is outside the internal network
    action flow_action_port_forward_outside_network(WidePortId_t egress_port, macAddr_t dst_mac) {
        flow_action_port_forward_within_network(egress_port, dst_mac);

        //Remove header(s) which are only used within the internal network, e.g. for inter-switch communication
        hdr.ethernet.etherType = hdr.inference.etherType;
        hdr.inference.setInvalid();
    }

    //Executes an action based on the flow's label
    table flow_action_table {
        key = { user_meta.flow_data.label: exact; }
        actions = { flow_action_drop; flow_action_port_forward_outside_network; flow_action_port_forward_within_network; }
        size = VALID_LABEL_COUNT + 1;
        default_action = flow_action_drop();
    }

    ///////////////////////////
    // REPORTING, MONITORING //
    ///////////////////////////

    //Adds a reporting header to the packet or not depending on the mutated flow ID hash.
    //  The control plane can fill the table according to what portion of the flows should be reported.
    action add_reporting_header() {
        hdr.reporting.setValid();
        hdr.reporting.flow_id = user_meta.flow_id;
        hdr.reporting.features = user_meta.features;
        //label_t accepted_label:
        hdr.reporting.accepted_label = user_meta.flow_data.label;
        //label_t latest_label:
        hdr.reporting.latest_label = user_meta.rf.verdict_label;
        //certainty_sum_t latest_label_certainty_sum:
        hdr.reporting.latest_label_certainty_sum = user_meta.rf.verdict_certainty_sum;
        //dt_count_t latest_label_dt_count:
        hdr.reporting.latest_label_dt_count = hdr.inference.executed_dt_count;

        ig_tm_md.copy_to_cpu = 1;
        hdr.i2e.reporting_header_valid = 1;
    }
    action no_reporting_header() {
        hdr.i2e.reporting_header_valid = 0;
    }
    table add_reporting_header_if_necessary_table {
        key = { user_meta.mutated_hashed_flow_id: range; }
        actions = { add_reporting_header; no_reporting_header; }
        default_action = no_reporting_header();
    }

    //Value used to modify the flow id to mitigate clients being able to predict which flows are going to be reported.
    //  TODO The value should be randomized on switch startup.
    const hashed_flow_id_t reporting_flow_id_mutator = 0x1234;

    ///////////
    // APPLY //
    ///////////

    apply { @atomic {
        //Calculate the flow ID
        //Treat forward and backward direction (e.g. TCP payload and ACK) as the same flow
        user_meta.flow_id = {
            min(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr),
            max(hdr.ipv4.srcAddr, hdr.ipv4.dstAddr),
            hdr.ipv4.protocol,
            user_meta.port_src,
            user_meta.port_dst
        };

        //Fix (flip) the port numbers if the lower IP is the source IP (because the IPs have already been flipped)
        if (!hdr.ipv4.isValid()) {
            //The 'reject' state in the parser is not implemented: it is the same as accept.
            //This if statement is placed here to avoid wasting a pipeline stage.
            ig_dprsr_md.drop_ctl = 1;
            exit;
        } else if (user_meta.flow_id.ip_lower == hdr.ipv4.dstAddr) {
            user_meta.flow_id.port_at_lower = user_meta.port_dst;
            user_meta.flow_id.port_at_upper = user_meta.port_src;
        }

        user_meta.hashed_flow_id = (hashed_flow_id_t) hash_crc32.get({
                    user_meta.flow_id.ip_lower, user_meta.flow_id.ip_upper,
                    user_meta.flow_id.protocol,
                    user_meta.flow_id.port_at_lower, user_meta.flow_id.port_at_upper
                });

        //////////////
        // FEATURES //
        //////////////

        user_meta.reset_flow_data = (bit<1>) flow_data_timeout_register_action.execute(user_meta.hashed_flow_id);

        user_meta.features.port_client = HASH_EXECUTE_ACTION(flow_data_port_client_register);
        //We could also use a register to save the server port, but this solution:
        // - doesn't seem to use more pipeline stages
        // - uses less registers (memory)
        if (user_meta.port_src == user_meta.features.port_client) { user_meta.features.port_server = user_meta.port_dst; }
                                                             else { user_meta.features.port_server = user_meta.port_src; }

        //Some not used features are disabled to save resources
        user_meta.features.length_current = hdr.ipv4.totalLen;
        user_meta.features.length_min = 0; //HASH_EXECUTE_ACTION(feature_length_min_register);
        user_meta.features.length_max = HASH_EXECUTE_ACTION(feature_length_max_register);
        user_meta.features.length_sum = HASH_EXECUTE_ACTION(feature_length_sum_register);

        user_meta.features.count = HASH_EXECUTE_ACTION(feature_count_register);

        if (user_meta.reset_flow_data == 0) {
            user_meta.features.count_tcp_syn = HASH_EXECUTE_ACTION(feature_count_tcp_syn_register);
            user_meta.features.count_tcp_ack = HASH_EXECUTE_ACTION(feature_count_tcp_ack_register);
            user_meta.features.count_tcp_psh = 0; //HASH_EXECUTE_ACTION(feature_count_tcp_psh_register);
            user_meta.features.count_tcp_fin = 0; //HASH_EXECUTE_ACTION(feature_count_tcp_fin_register);
            user_meta.features.count_tcp_rst = HASH_EXECUTE_ACTION(feature_count_tcp_rst_register);
            user_meta.features.count_tcp_ece = 0; //HASH_EXECUTE_ACTION(feature_count_tcp_ece_register);
        } else {
            user_meta.features.count_tcp_syn = HASH_EXECUTE_RESET_ACTION(feature_count_tcp_syn_register);
            user_meta.features.count_tcp_ack = HASH_EXECUTE_RESET_ACTION(feature_count_tcp_ack_register);
            user_meta.features.count_tcp_psh = 0; //HASH_EXECUTE_RESET_ACTION(feature_count_tcp_psh_register);
            user_meta.features.count_tcp_fin = 0; //HASH_EXECUTE_RESET_ACTION(feature_count_tcp_fin_register);
            user_meta.features.count_tcp_rst = HASH_EXECUTE_RESET_ACTION(feature_count_tcp_rst_register);
            user_meta.features.count_tcp_ece = 0; //HASH_EXECUTE_RESET_ACTION(feature_count_tcp_ece_register);
        }

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
                error "Source code doesn't match configuration; please check this error's source location."
            #endif
        }

        //Apply each decision tree in the random forest (if an RF is available)
        if (hdr.inference.rf_id != RF_ID_DONT_CLASSIFY) {
            dt_id_bitflag_table.apply();
            //The following if statements "waste" a stage, but they are necessary. An alternative is to change the
            //  condition into a table key, but that also uses up a stage: there are too many keys to fit in one stage.
            if (user_meta.rf.dt_execute_0) { dt_0_table.apply(); }
            if (user_meta.rf.dt_execute_1) { dt_1_table.apply(); }
            #if DT_PER_SWITCH_COUNT != 2
                error "Source code doesn't match configuration; please check this error's source location."
            #endif
        }

        //Try to determine the label if enough DTs have been executed
        //Any switch on the packet's path can calculate the label and act on it. For example, the switch can drop
        //  the packet and reduce load on subsequent switches. Another approach (not implemented here) is to only
        //  add the following logic to specific "edge" switches, saving resources on the other switches.
        if (user_meta.features.count > MAX_CLASSIFIABLE_FLOW_LENGTH) {
            //Don't do anything, leave the verdict unset
            //We combine this branch with the one below because of a Tofino limitation
        } else if (hdr.inference.executed_dt_count >= DT_COUNT_REQUIRED_TO_SET_LABEL) {
            //Calculate the verdict of the random forest, taking certainty thresholds into account
            certainties_to_verdict_table.apply();

            //Save the new flow label if it's set and if the old flow label isn't set
            user_meta.flow_data.label = HASH_EXECUTE_ACTION(flow_data_label_register);
        }

        ////////////////////////////////////////////////////////
        // LABEL HANDLING, REPORTING, SENDING DATA TO INGRESS //
        ////////////////////////////////////////////////////////

        hdr.i2e.setValid(); //For passing data from ingress to egress

        user_meta.mutated_hashed_flow_id = user_meta.hashed_flow_id ^ reporting_flow_id_mutator;
        add_reporting_header_if_necessary_table.apply();

        //This table uses user_meta.flow_data.label as its key and invalidates the inference header
        flow_action_table.apply();
    } /* end @atomic */ }
}
