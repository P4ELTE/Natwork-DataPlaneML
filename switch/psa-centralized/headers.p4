header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    etherType_t etherType;
}

//Represents a packet that has been classified by the control plane.
header classified_t {
    etherType_t etherType;  // Ether type of the original packet
    label_t label;  // Label assigned to the packet by the control plane
}

//If needed, separate ingress and egress headers are possible
struct headers_t {
    ethernet_t ethernet;
    classified_t classified;
}
