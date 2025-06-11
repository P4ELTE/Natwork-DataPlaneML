//Flows that have transmitted too many packets shouldn't be classified because features might have overflowed.
//  This value is the maximum packet count where classification is still allowed.
//  When setting this value, consider the bit width of feature_count_t: that value is used to store packet counts.
//  This value can also have a great impact on the memory requirements of the controller.
#define MAX_CLASSIFIABLE_FLOW_LENGTH 32

//At most how many random forests to use
#define MAX_RF_COUNT 6

//How many decision trees each random forest should consist of
#define DT_PER_RF_COUNT 2
// pForests uses 3 RFs and 32 decision trees of depth 10 (per RF)

//How many decision trees each switch should be able to store
#define DT_PER_SWITCH_COUNT 2
#if DT_PER_SWITCH_COUNT > DT_PER_RF_COUNT
    error "Source code doesn't match configuration; please check this error's source location."
#endif

//The RF may be distributed across multiple switches. This value is the minimum number of DTs that need to have been
//  executed before a label can be set based on the majority vote of the DTs.
//  Usually, this value should be equal to DT_PER_RF_COUNT.
#define DT_COUNT_REQUIRED_TO_SET_LABEL DT_PER_RF_COUNT
#if DT_COUNT_REQUIRED_TO_SET_LABEL > DT_PER_RF_COUNT
    error "Source code doesn't match configuration; please check this error's source location."
#endif

//At most how many "levels" a decision tree should have. The root is at depth 0. Leaf count <= 2^MAX_DT_DEPTH
#define MAX_DT_DEPTH 5

//Converts the specified amount of time into the (platform-specific) time units
#define MILLIS_TO_TIME_UNITS(MS) (MS * 1000)
#define SEC_TO_TIME_UNITS(MS) MILLIS_TO_TIME_UNITS(MS * 1000)

//After how many time units flows should time out
#define FLOW_TIMEOUT_THRESHOLD SEC_TO_TIME_UNITS(3)
