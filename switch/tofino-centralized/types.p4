typedef bit<16> WidePortId_t; //PortId_t is 9 bits wide, which causes issues

typedef bit<16> etherType_t;
typedef bit<48> macAddr_t;

const etherType_t ETHER_TYPE_IPV4 = 0x0800; //2048
const etherType_t ETHER_TYPE_CLASSIFIED = 0x1236; //4662

typedef bit<8> label_t;
const label_t LABEL_NOT_SET = 0;
const label_t LABEL_BENIGN = 1;
const label_t LABEL_ATTACK = 2;
#define VALID_LABEL_COUNT 2

struct ingress_user_meta_t {}
struct egress_user_meta_t {}
