import dataclasses
import enum
import socket
import struct
from typing import List, Tuple

import dpkt
import numpy as np


@dataclasses.dataclass(frozen=True)
class FlowId:
    """
    Identifier of a specific flow. The forward and backward direction of a flow are treated as the same flow.
    """

    ip_lower: int
    ip_upper: int
    protocol: int
    port_at_lower: int
    port_at_upper: int

    def to_tuple(self) -> Tuple[int, int, int, int, int]:
        """Returns each field of a flow ID as a tuple."""
        return self.ip_lower, self.ip_upper, self.protocol, self.port_at_lower, self.port_at_upper

    @staticmethod
    def from_values(ip_src: int, ip_dst: int, protocol: int, port_src: int, port_dst: int) -> 'FlowId':
        """Parses a flow ID from integer values."""
        # Treat forward and backward direction (e.g. TCP payload and ACK) as the same flow
        if ip_src > ip_dst:
            ip_src, ip_dst = ip_dst, ip_src
            port_src, port_dst = port_dst, port_src
        elif ip_src == ip_dst and port_src > port_dst:
            port_src, port_dst = port_dst, port_src
        return FlowId(ip_src, ip_dst, protocol, port_src, port_dst)

    @staticmethod
    def from_ndarray(a: np.ndarray, start_index: int = 0) -> 'FlowId':
        """Parses a flow ID from a numpy array."""
        # noinspection PyTypeChecker
        return FlowId.from_values(a[start_index], a[start_index + 1], a[start_index + 2], a[start_index + 3],
                                  a[start_index + 4])

    @staticmethod
    def from_strings(ip_src: str, ip_dst: str, protocol: str, port_src: str, port_dst: str) -> 'FlowId':
        """Parses a flow ID from string values."""
        return FlowId.from_values(_ip_str_to_int(ip_src), _ip_str_to_int(ip_dst),
                                  int(protocol), int(port_src), int(port_dst))

    @staticmethod
    def from_dpkt_packet(ip: dpkt.ip.IP) -> 'FlowId':
        """Parses a flow ID from a DPKT packet (more specifically, from an IP header)."""
        if isinstance(ip.data, dpkt.tcp.TCP) or isinstance(ip.data, dpkt.udp.UDP):
            port_src, port_dst = ip.data.sport, ip.data.dport
        else:
            port_src, port_dst = 0, 0
        return FlowId.from_values(ip.src, ip.dst, ip.p, port_src, port_dst)

    def to_tcpdump_filter(self) -> str:
        """Returns a tcpdump filter string that matches packets belonging to this flow."""
        forward = f"ip src {_ip_int_to_str(self.ip_lower)} and ip dst {_ip_int_to_str(self.ip_upper)} and " \
                  f"proto {self.protocol}"
        reverse = f"ip src {_ip_int_to_str(self.ip_upper)} and ip dst {_ip_int_to_str(self.ip_lower)} and " \
                  f"proto {self.protocol}"
        if self.protocol == 0x06 or self.protocol == 0x11:
            forward += f" and src port {self.port_at_lower} and dst port {self.port_at_upper}"
            reverse += f" and src port {self.port_at_upper} and dst port {self.port_at_lower}"
        return f"'({forward}) or ({reverse})'"

    def __repr__(self) -> str:
        pair_a = f"{_ip_int_to_str(self.ip_lower)}:{self.port_at_lower}"
        pair_b = f"{_ip_int_to_str(self.ip_upper)}:{self.port_at_upper}"
        return f"<{pair_a}-{pair_b}#{self.protocol}>"


_IP_STRUCT = struct.Struct('!L')
"""Format used to convert IP addresses between integer and byte representations."""


def _ip_str_to_int(x: str) -> int:
    """Converts an IP address string (e.g. 123.45.67.89) to an integer (e.g. 0x89ABCDEF)."""
    return _IP_STRUCT.unpack(socket.inet_aton(x))[0]


def _ip_int_to_str(x: int) -> str:
    """Converts an IP address integer (e.g. 0x89ABCDEF) to a string (e.g. 123.45.67.89)."""
    return socket.inet_ntoa(_IP_STRUCT.pack(x))


class Feature(enum.IntEnum):
    """
    The different features that are extracted from flows.
    The value of each enum element (feature) can be used to index feature vectors to retrieve the corresponding feature,
    and the enum values are sometimes also used as the numerical reference to the given feature.
    """

    COUNT = 0
    IAT_MIN = enum.auto()
    IAT_MAX = enum.auto()
    IAT_AVG = enum.auto()
    LENGTH_MIN = enum.auto()
    LENGTH_MAX = enum.auto()
    LENGTH_AVG = enum.auto()
    LENGTH_SUM = enum.auto()
    COUNT_TCP_SYN = enum.auto()
    COUNT_TCP_ACK = enum.auto()
    COUNT_TCP_PSH = enum.auto()
    COUNT_TCP_FIN = enum.auto()
    COUNT_TCP_RST = enum.auto()
    COUNT_TCP_ECE = enum.auto()
    DURATION = enum.auto()
    PORT_CLIENT = enum.auto()
    PORT_SERVER = enum.auto()
    LENGTH_CURRENT = enum.auto()

    @classmethod
    def enabled_features(cls) -> List['Feature']:
        """
        The features that are allowed to be used in the classification process.
        Some features might be blacklisted because e.g. Tofino does not support them.
        The relative order of the features is preserved in the returned subset.
        """
        # return [x for x in Feature]
        return [cls.LENGTH_MAX, cls.LENGTH_SUM, cls.COUNT_TCP_SYN, cls.COUNT_TCP_ACK, cls.COUNT_TCP_RST,
                cls.PORT_CLIENT, cls.PORT_SERVER, cls.LENGTH_CURRENT]

    @classmethod
    def disabled_features(cls) -> List['Feature']:
        """The opposite of `enabled_features()`. Contains all features that are not allowed to be used."""
        return [x for x in Feature if x not in cls.enabled_features()]

    @classmethod
    def time_based_features(cls) -> List['Feature']:
        """
        The features which take packet timestamps into account.
        They require real-time network simulation or packet replay.
        """
        return [cls.IAT_MIN, cls.IAT_MAX, cls.IAT_AVG, cls.DURATION]

    @property
    def max_value(self) -> int:
        """Returns the maximum value that the feature can have."""
        if self in self.time_based_features():
            return np.iinfo(np.uint32).max
        if 'COUNT' in self.name:
            return np.iinfo(np.uint8).max
        return np.iinfo(np.uint16).max


class Label(enum.IntEnum):
    """
    The different labels that can be assigned to flows, including a "no label assigned" value.
    The value of each enum element (label) is the numerical representation of the label.
    """

    NOT_SET = 0
    BENIGN = enum.auto()
    ATTACK = enum.auto()

    @classmethod
    def excluding_not_set(cls) -> List['Label']:
        """Returns all possible labels, excluding the label corresponding to the "no label assigned" value."""
        return [x for x in Label if x != Label.NOT_SET]

    @classmethod
    def compute_count_statistics(cls, labels: 'ListOfLabelSchema', counts: np.ndarray = None,
                                 min_count: int = 0) -> str:
        """
        Returns a string with the statistics of the given list of labels.
        Optionally uses the provided bin counts, otherwise calculates them.
        Optionally filters out labels that didn't appear at least `min_count` times.
        """
        if counts is None:
            counts = np.bincount(labels, minlength=len(Label))
            total_count = len(labels)
        else:
            total_count = np.sum(counts)
        pairs = (f"{label.name}: {count} ({round(count / total_count * 100)}%)"
                 for label, count in zip(Label, counts) if count > min_count)
        return "; ".join(pairs)


class FlowDataCols(enum.IntEnum):
    """
    Columns of flow-data related schemas. The values of the enum elements can be used as indices to access the columns.
    The values (e.g. total count, last seen ms) might not get updated after the packet count reaches the
    MAX_CLASSIFIABLE_FLOW_LENGTH constant.
    """
    IP_LOWER = 0  # A field in the flow ID
    IP_UPPER = enum.auto()  # A field in the flow ID
    PROTOCOL = enum.auto()  # A field in the flow ID
    PORT_AT_LOWER = enum.auto()  # A field in the flow ID
    PORT_AT_UPPER = enum.auto()  # A field in the flow ID
    SWITCH_ORDINAL = enum.auto()  # Only set if applicable, otherwise can be any value
    TOTAL_COUNT = enum.auto()  # Total flow length, can be used to e.g. index into a flow length -> feature mapping
    FIRST_SEEN_MS = enum.auto()  # Relative to some sort of "start time" (because of the 32-bit limit)
    LAST_SEEN_MS = enum.auto()  # Relative to some sort of "start time" (because of the 32-bit limit)

    @staticmethod
    def flow_id_begin() -> 'FlowDataCols':
        """The first column of the flow ID. The flow ID is stored in the columns [flow_id_begin, flow_id_end)."""
        return FlowDataCols.IP_LOWER

    @staticmethod
    def flow_id_end() -> 'FlowDataCols':
        """The last column of the flow ID. The flow ID is stored in the columns [flow_id_begin, flow_id_end)."""
        return FlowDataCols.PORT_AT_UPPER


class FlowPredCols(enum.IntEnum):
    """
    Columns of prediction-related related schemas.
    The values of the enum elements can be used as indices to access the columns.
    """
    PREDICTED_LABEL = 0  # Label calculated by e.g. the in-network classifier (if applicable)
    PREDICTED_AT_COUNT = enum.auto()  # Flow length at which the predicted label was accepted (if applicable)
    # We could also save the certainty if we wanted to


FeatureSchema = np.ndarray
"""
A numpy array containing a specific flow's features at a specific flow length.
Indexing: [feature_index]. Data type: uint32.
"""

ListOfFeaturesSchema = np.ndarray
"""
A numpy array containing flow features of various flow lengths of multiple flows.
Indexing: [n, flow_length, feature_index]. Data type: uint32.
"""

ListOfLabelSchema = np.ndarray
"""
A numpy array containing flow labels of multiple flows.
Indexing: [n]. Data type: uint32.
"""

ListOfFlowDataSchema = np.ndarray
"""
A numpy array containing various data about flows (see `FlowDataCols`).
Indexing: [n, column_index]. Data type: uint32.
"""

ListOfFlowPredSchema = np.ndarray
"""
A numpy array containing the columns defined in `FlowPredCols`.
Indexing: [n, column_index]. Data type: uint32.
"""
