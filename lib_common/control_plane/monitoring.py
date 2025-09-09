import logging
from typing import List

from lib_common.control_plane.data import ControlledSwitch, Network
from lib_common.data import SwitchConstants
from p4_api_bridge import ApiBridge, TofinoShellApiConfig

_logger = logging.getLogger(__name__)


def configure_reporting(switch_constants: SwitchConstants, network: Network, flow_report_ratio: float) -> None:
    """Initializes the monitoring system on the network."""
    for switch in network.controlled_switches:
        # Tofino doesn't require multicast groups, it can clone to the CPU in a simpler way
        if not isinstance(switch.config.switch_type, TofinoShellApiConfig):
            _create_report_multicast_groups(switch)

    # Set the CPU port register
    for switch in network.controlled_switches:
        if not isinstance(switch.config.switch_type, TofinoShellApiConfig):
            # Tofino switches don't need (therefore don't have) this register
            switch.api.register_set('MyIngress.cpu_port_register', 0, switch.cpu_interface[0])

    # Not all switches should report data: if a flow passes through multiple switches,
    # then only the ones should report that are capable of determining the flow's label, to not waste bandwidth.
    # For example, only the edge switches should report data (if packets aren't dropped based on their label).
    reporting_switches: List[ControlledSwitch] = [
        # TODO don't hardcode this; this should depend on the model and the network topology
        # Only the last switch, e.g. s2 if there are 2 switches
        max(network.controlled_switches, key=lambda s: int(s.name[1:]))
    ]
    _logger.info(f"Switches that are allowed to report: {', '.join(s.name for s in reporting_switches)}")

    # per_switch_flow_report_ratio = monitored_flow_ratio / len(network.controlled_switches)
    # TODO For now switches share their random seed => the monitored flows will be the same on all switches
    per_switch_flow_report_ratio = flow_report_ratio

    for switch in network.controlled_switches:
        this_switch_ratio = per_switch_flow_report_ratio if switch in reporting_switches else 0
        _logger.info(f"Switch {switch.name} will report {this_switch_ratio * 100:.2f}% of flows")

        max_hash = round(((2 ** switch_constants.hashed_flow_id_width) - 1) * per_switch_flow_report_ratio)
        # This branching is necessary because PSA doesn't support range matches
        if isinstance(switch.config.switch_type, TofinoShellApiConfig):
            switch.api.table_clear("MyIngress.add_reporting_header_if_necessary_table")
            if switch in reporting_switches:
                switch.api.table_add("MyIngress.add_reporting_header_if_necessary_table", [f"0..{max_hash}"],
                                     "MyIngress.add_reporting_header", [])
        else:
            switch.api.register_set("MyIngress.reported_flow_max_hash_register", 0,
                                    max_hash if switch in reporting_switches else 0)


def _create_report_multicast_groups(switch: ControlledSwitch) -> None:
    """
    Installs multicast groups on the switch that can be used for cloning report messages to the controller.
    Multicast groups are used instead of clone sessions due to an eBPF-PSA limitation:
    https://github.com/p4lang/p4c/issues/4958
    """
    _logger.info(f"Creating report multicast group for each egress interface for switch {switch.name}")

    for interface in switch.all_interfaces:
        if interface == switch.cpu_interface[0]:  # Skip the CPU port: we are interested in the real ports
            continue

        # The multicast group ID is the same as the port number it forwards to in addition to the CPU port
        group_id = switch.api.translate_interface_to_port(interface)
        assert group_id != 0  # Number 0 is not a valid group ID
        switch.api.multicast_group_create(group_id, [
            ApiBridge.MulticastGroupMember(
                    egress_interface=interface,
                    instance_id=0  # Not used
            ),
            ApiBridge.MulticastGroupMember(
                    egress_interface=switch.cpu_interface[0],
                    instance_id=0  # Not used
            )
        ])
