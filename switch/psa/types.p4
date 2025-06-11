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
    TimestampUint_t timestamp_first; //When the first packet of this flow arrived
    TimestampUint_t timestamp_previous; //When the previous packet arrived
    TimestampUint_t iat_latest; //Arrival time difference between this packet and the previous one
    protocol_port_t port_client; //Port of the client (the one that sent the first packet)
    protocol_port_t port_server; //Port of the server (the one that received the first packet)
    label_t label; //Classification of this flow
}

//////////////
// features //
//////////////

//Keep in mind that computing averages requires some extra free bits to avoid overflow:
// we can't compute averages of 64 bit wide types, except if the top few bits are always zero.

typedef bit<8> feature_count_t;
#define FEATURE_IAT_WIDTH 32
typedef bit<FEATURE_IAT_WIDTH> feature_iat_t;
const feature_iat_t FEATURE_IAT_MAX = (1 << FEATURE_IAT_WIDTH) - 1;
#define FEATURE_LENGTH_WIDTH 16
typedef bit<FEATURE_LENGTH_WIDTH> feature_length_t;
typedef bit<FEATURE_LENGTH_WIDTH> feature_length_sum_t; //16 bits due to a Tofino limitation
const feature_length_sum_t FEATURE_LENGTH_SUM_MAX = (1 << FEATURE_LENGTH_WIDTH) - 1;
typedef bit<8> feature_count_tcp_t;
typedef bit<32> feature_duration_t;

struct features_t { //Source: pForest, Table 1
    // --- Features stored in registers ---
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

    // --- Computed features without their own registers ---
    //Time since first packet
    feature_duration_t duration;

    // --- Stateless features read from current packet ---
    //TCP/UDP port (client is the one that sent the first packet)
    protocol_port_t port_client;
    protocol_port_t port_server;
    //Length of current packet
    feature_length_t length_current;
}

//////////////
// RFs, DTs //
//////////////

typedef bit<32> dt_bitflag_t;
#if DT_PER_RF_COUNT > 32  //32 bits wide bitflag -> we can identify up to 32 DTs
    #error "Source code doesn't match configuration; please check this error's source location."
#endif

typedef bit<8> dt_count_t;
typedef bit<5> dt_id_t;  //Shift amount is limited to 5 bits on eBPF

typedef bit<8> certainty_t;
typedef bit<16> certainty_sum_t;
typedef bit<8> rf_id_t;
typedef bit<16> node_id_t;

const rf_id_t RF_ID_DONT_CLASSIFY = 0;

struct dt_t {
    //Table keys
    rf_id_t rf_id;  //Set to RF_ID_DONT_CLASSIFY when a leaf node is encountered in the DT
    node_id_t node_id;
    bit<1> threshold_passed;  //"passed" means the feature value is greater than the threshold
}

struct rf_t {
    //Verdict based on the aggregated data from the DTs
    label_t verdict_label; //The label with the highest certainty sum
    certainty_sum_t verdict_certainty_sum;
}

//////////////////////
// temporary fields //
//////////////////////

//A table cannot be applied within an action and some other restrictions also apply to actions.
//  To work around them, we use temporary variables.

struct tmp_l3_forward_t { //Because tables cannot be applied within actions
    bit<1> drop; //whether to drop the packet
    PortId_t egress_port; //ignored if drop is set
    macAddr_t dst_mac; //ignored if drop is set
    bool leaves_network; //whether the packet leaves the internal network; ignored if drop is set
}

//////////
// meta //
//////////

//The eBPF-PSA compiler differs from the specification and uses the same metadata for the ingress and egress pipeline.
//  On top of that, the user meta is passed from the ingress to the egress pipeline. We exploit this bug because:
//   1) It makes the implementation much simpler
//   2) Due to another issue with the compiler, several other metadata-passing methods don't work
//       (The only alternative is to pass data using headers, but parsing a header with a struct field is unsupported)
//  Link to the GitHub issue: https://github.com/p4lang/p4c/issues/4983
struct user_meta_t {
    flow_id_t flow_id;
    hashed_flow_id_t hashed_flow_id;
    hashed_flow_id_t mutated_hashed_flow_id;
    flow_data_t flow_data;
    features_t features;
    dt_t dt;
    rf_t rf;
    tmp_l3_forward_t tmp_l3_forward;
    PortId_t cpu_port;
}

struct resubmit_meta_t {}
struct recirculate_meta_t {}
struct normal_meta_t {}
struct clone_i2e_meta_t {}
struct clone_e2e_meta_t {}
