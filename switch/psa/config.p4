//At most how many IPv4 LPM-based forwarding table entries should be supported.
#define L3_TABLE_SIZE 256

//Some features use averages, which are computed using exponential moving averages.
//  If this value is X, then the alpha value will be 1/(2^X). For example, a value of 8 yield alpha = 1/256.
#define FEATURE_AVERAGE_SMOOTHING 2

//Flows that have transmitted too many packets shouldn't be classified because features might have overflowed.
//  This value is the maximum packet count where classification is still allowed.
//  When setting this value, consider the bit width of feature_count_t: that value is used to store packet counts.
//  This value can also have a great impact on the memory requirements of the controller.
#define MAX_CLASSIFIABLE_FLOW_LENGTH 32

//At most how many random forests to use
#define MAX_RF_COUNT 8

//Linux kernel limitation: the maximum number of BPF maps that can be created per program is 64.
// With p4c-ebpf, each P4 table is implemented as two BPF maps, and registers also use BPF maps.
// Therefore we are severely limited in how many and how deep DTs we are able to use.

//How many decision trees each random forest should consist of
#define DT_PER_RF_COUNT 6
// pForests uses 3 RFs and 32 decision trees of depth 10 (per RF)

//How many decision trees each switch should be able to store
#define DT_PER_SWITCH_COUNT 2
#if DT_PER_SWITCH_COUNT > DT_PER_RF_COUNT
    #error "Source code doesn't match configuration; please check this error's source location."
#endif

//The RF may be distributed across multiple switches. This value is the minimum number of DTs that need to have been
//  executed before a label can be set based on the majority vote of the DTs.
//  Usually, this value should be equal to DT_PER_RF_COUNT.
#define DT_COUNT_REQUIRED_TO_SET_LABEL DT_PER_RF_COUNT
#if DT_COUNT_REQUIRED_TO_SET_LABEL > DT_PER_RF_COUNT
    #error "Source code doesn't match configuration; please check this error's source location."
#endif

//At most how many "levels" a decision tree should have. The root is at depth 0. Leaf count = 2^MAX_DT_DEPTH
#define MAX_DT_DEPTH 7

//Converts the specified amount of time into the (platform-specific) time units
#define MILLIS_TO_TIME_UNITS(MS) (MS * 1000)
#define SEC_TO_TIME_UNITS(MS) MILLIS_TO_TIME_UNITS(MS * 1000)

//After how many time units (e.g. nanoseconds in case of Tofino) flows should time out
#define FLOW_TIMEOUT_THRESHOLD SEC_TO_TIME_UNITS(3)
