//////////
// misc //
//////////

// We use 64 bits because it's hard to work with 48 bits (can't store them in registers)
typedef bit<32> timestamp_t;
const int TIMESTAMP_SHIFT_AMOUNT = 10; //Division by 1024, converts from nanoseconds to microseconds

typedef bit<16> WidePortId_t; //PortId_t is 9 bits wide, which causes issues

/////////////
// parsing //
/////////////

//Ethernet
typedef bit<16> etherType_t;
typedef bit<48> macAddr_t;

const etherType_t ETHER_TYPE_IPV4 = 0x0800; //2048
const etherType_t ETHER_TYPE_REPORTING = 0x1234; //4660
const etherType_t ETHER_TYPE_INFERENCE = 0x1235; //4661

//IPv4, UDP, TCP
typedef bit<32> ip4Addr_t;
typedef bit<8> protocol_t;
typedef bit<16> protocol_port_t;

const protocol_t IPV4_PROTOCOL_TCP = 0x06; //6
const protocol_t IPV4_PROTOCOL_UDP = 0x11; //17

/////////////
// flow id //
/////////////

struct flow_id_t {
    ip4Addr_t ip_lower;
    ip4Addr_t ip_upper;
    protocol_t protocol;
    protocol_port_t port_at_lower;
    protocol_port_t port_at_upper;
}

//Bit width of hashed flow identifiers. This also determines the size of the "hash-table" registers.
#define HASHED_FLOW_ID_WIDTH 16
typedef bit<HASHED_FLOW_ID_WIDTH> hashed_flow_id_t;

///////////////
// flow data //
///////////////

typedef bit<8> label_t;
const label_t LABEL_NOT_SET = 0;
const label_t LABEL_BENIGN = 1;
const label_t LABEL_ATTACK = 2;
#define VALID_LABEL_COUNT 2

struct flow_data_t {
    label_t label; //Classification of this flow
}

//////////////
// features //
//////////////

typedef bit<8> feature_count_t;
typedef bit<32> feature_iat_t;
typedef bit<16> feature_length_t;
const feature_length_t FEATURE_LENGTH_MAX = 0xFFFF; //65535
//Can't use more than 20 bits when field is used as a range match key. Because of this the length sum can easily
//  overflow, but we can use saturation arithmetic to prevent this.
typedef bit<16> feature_length_sum_t;
typedef bit<8> feature_count_tcp_t;
typedef bit<32> feature_duration_t;

struct features_t { //Source: pForest, Table 1
    //Number of packets
    feature_count_t count;
    //Packet inter-arrival time
    feature_iat_t iat_min;
    feature_iat_t iat_max;
    feature_iat_t iat_avg;
    //Packet length
    feature_length_t length_min;
    feature_length_t length_max;
    feature_length_t length_avg;
    feature_length_sum_t length_sum;
    //TCP flag counts
    feature_count_tcp_t count_tcp_syn;
    feature_count_tcp_t count_tcp_ack;
    feature_count_tcp_t count_tcp_psh;
    feature_count_tcp_t count_tcp_fin;
    feature_count_tcp_t count_tcp_rst;
    feature_count_tcp_t count_tcp_ece;
    //Time since first packet
    feature_duration_t duration;
    //TCP/UDP port
    protocol_port_t port_client; //Port of the client (the one that sent the first packet)
    protocol_port_t port_server; //Port of the server (the one that received the first packet)
    //Length of current packet
    feature_length_t length_current;
}

//////////////
// RFs, DTs //
//////////////

typedef bit<32> dt_bitflag_t;
#if DT_PER_RF_COUNT > 32  //32 bits wide bitflag -> we can identify up to 32 DTs
    error "Source code doesn't match configuration; please check this error's source location."
#endif

typedef bit<8> dt_count_t;

typedef bit<8> certainty_t;
typedef bit<16> certainty_sum_t;
typedef bit<8> rf_id_t;

const rf_id_t RF_ID_DONT_CLASSIFY = 0;

struct rf_t {
    //Verdict based on the aggregated data from the DTs
    label_t verdict_label; //The label with the highest certainty sum if the threshold and other checks pass, otherwise LABEL_NOT_SET
    certainty_sum_t verdict_certainty_sum;

    //Flags for each DT: whether it should be executed (these are not part of RF_T_FIELDS_FOR_DT for alignment reasons)
    bool dt_execute_0; bool dt_execute_1;
    #if DT_PER_SWITCH_COUNT != 2
        error "Source code doesn't match configuration; please check this error's source location."
    #endif
}

//////////
// meta //
//////////

struct ingress_user_meta_t {
    protocol_port_t port_src;
    protocol_port_t port_dst;
    flow_id_t flow_id;
    hashed_flow_id_t hashed_flow_id;
    hashed_flow_id_t mutated_hashed_flow_id;
    flow_data_t flow_data;
    features_t features;
    rf_t rf;
    bit<1> reset_flow_data;
}

struct egress_user_meta_t {}
