import dataclasses
import struct

NIKSS_PIPE_ID_OFFSET = 200
"""
The offset used when NIKSS pipelines are being created.
This offset aims to minimize the chance of conflicting with others' BPF programs.
"""

REPORT_HEADER_ETHER_TYPE = 0x1234
"""
The Ethernet packet type used by report packets.
Defined in: types.p4
"""

FLOW_ID_STRUCT = struct.Struct('! 2I B 2H')
"""Format used to pack and unpack flow IDs when transmitting them over the network."""

FEATURE_STRUCT = struct.Struct('! B 3I 4H 6B I 3H')
"""Format used to pack and unpack features when transmitting them over the network."""

REPORT_HEADER_OTHER_FIELDS_STRUCT = struct.Struct('! 2B H B')
"""Format used to pack and unpack the fields of the report header that are not part of the flow ID or features."""


@dataclasses.dataclass(frozen=True)
class SwitchConstants:
    """Switch-related constants. This class holds the values defined in the config.p4 file."""

    mtu: int
    """The maximum transmission unit that can be processed. This also considers any extra headers switches might add."""

    max_classifiable_flow_length: int
    """
    The maximum packet count within a flow at which a flow can still be classified.
    Defined in: config.p4
    """

    certainty_type_width: int
    """
    The bit width of certainty values.
    Defined in: types.p4
    """

    hashed_flow_id_width: int
    """
    The bit width of hashed flow identifiers.
    Defined in: types.p4
    """

    max_rf_count: int
    dt_per_rf_count: int
    dt_per_switch_count: int
    dt_count_required_to_set_label: int
    max_dt_depth: int

    @property
    def certainty_type_max_value(self) -> int:
        """Returns the maximum certainty value."""
        return (2 ** self.certainty_type_width) - 1

    def __post_init__(self) -> None:
        # Sanity-check the values
        if self.dt_count_required_to_set_label > self.dt_per_rf_count:
            raise ValueError("dt_count_required_to_set_label cannot be greater than dt_per_rf_count")

    @staticmethod
    def create_ebpf() -> 'SwitchConstants':
        """Creates an instance containing appropriate values for eBPF switches."""
        return SwitchConstants(
                mtu=3506,
                # BPF limitation, see https://ebpf-docs.dylanreimerink.nl/linux/program-type/BPF_PROG_TYPE_XDP/#max-mtu)
                max_classifiable_flow_length=32,
                certainty_type_width=8,
                hashed_flow_id_width=16,
                max_rf_count=8,
                dt_per_rf_count=6,
                dt_per_switch_count=2,
                dt_count_required_to_set_label=6,
                max_dt_depth=7,
        )

    @staticmethod
    def create_tofino() -> 'SwitchConstants':
        """Creates an instance containing appropriate values for Tofino switches."""
        return SwitchConstants(
                mtu=1300,  # We had issues with higher MTU values, probably because of the extra headers
                max_classifiable_flow_length=32,
                certainty_type_width=8,
                hashed_flow_id_width=16,
                max_rf_count=6,
                dt_per_rf_count=2,
                dt_per_switch_count=2,
                dt_count_required_to_set_label=2,
                max_dt_depth=5,
        )
