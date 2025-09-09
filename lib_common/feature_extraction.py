import dpkt
import numpy as np

from lib_common.flow import Feature, FeatureSchema


def parse_packet(ip: dpkt.ip.IP) -> FeatureSchema:
    """Extracts values from the specified packet, similarly to the logic in the P4 code."""
    features = np.zeros(shape=(len(Feature),), dtype=np.uint32)
    features[Feature.COUNT] = 1
    features[Feature.LENGTH_MIN] = ip.len
    features[Feature.LENGTH_MAX] = ip.len
    # features[Feature.LENGTH_AVG] = ip.len
    features[Feature.LENGTH_SUM] = ip.len
    features[Feature.LENGTH_CURRENT] = ip.len

    if isinstance(ip.data, dpkt.tcp.TCP) or isinstance(ip.data, dpkt.udp.UDP):
        features[Feature.PORT_CLIENT] = ip.data.sport
        features[Feature.PORT_SERVER] = ip.data.dport

    if isinstance(ip.data, dpkt.tcp.TCP):
        flags = ip.data.flags
        # noinspection DuplicatedCode
        features[Feature.COUNT_TCP_SYN] = int(bool(flags & dpkt.tcp.TH_SYN))
        features[Feature.COUNT_TCP_ACK] = int(bool(flags & dpkt.tcp.TH_ACK))
        features[Feature.COUNT_TCP_PSH] = int(bool(flags & dpkt.tcp.TH_PUSH))
        # noinspection DuplicatedCode
        features[Feature.COUNT_TCP_FIN] = int(bool(flags & dpkt.tcp.TH_FIN))
        features[Feature.COUNT_TCP_RST] = int(bool(flags & dpkt.tcp.TH_RST))
        features[Feature.COUNT_TCP_ECE] = int(bool(flags & dpkt.tcp.TH_ECE))

    return features


def merge_features(stored_features: FeatureSchema, last_timestamp: int,
                   new_features: FeatureSchema, new_timestamp: int) -> None:
    """Merges the new features into the stored features."""
    # Averages and time-based features are not implemented, similarly to the P4 code
    stored_features[Feature.COUNT] += new_features[Feature.COUNT]
    stored_features[Feature.LENGTH_MIN] = min(int(stored_features[Feature.LENGTH_MIN]),
                                              int(new_features[Feature.LENGTH_MIN]))
    stored_features[Feature.LENGTH_MAX] = max(int(stored_features[Feature.LENGTH_MAX]),
                                              int(new_features[Feature.LENGTH_MAX]))
    stored_features[Feature.LENGTH_SUM] += new_features[Feature.LENGTH_SUM]
    stored_features[Feature.LENGTH_CURRENT] = new_features[Feature.LENGTH_CURRENT]

    stored_features[Feature.COUNT_TCP_SYN] += new_features[Feature.COUNT_TCP_SYN]
    stored_features[Feature.COUNT_TCP_ACK] += new_features[Feature.COUNT_TCP_ACK]
    stored_features[Feature.COUNT_TCP_PSH] += new_features[Feature.COUNT_TCP_PSH]
    stored_features[Feature.COUNT_TCP_FIN] += new_features[Feature.COUNT_TCP_FIN]
    stored_features[Feature.COUNT_TCP_RST] += new_features[Feature.COUNT_TCP_RST]
    stored_features[Feature.COUNT_TCP_ECE] += new_features[Feature.COUNT_TCP_ECE]
