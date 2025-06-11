import logging
from typing import List

from controller.data import ControlledSwitch, TrafficForwardingMethod, Network
from lib_common.flow import Label

_logger = logging.getLogger(__name__)


def configure_forwarding(network: Network) -> None:
    """Uploads data packet forwarding rules to the switches."""
    _logger.info("Configuring packet forwarding...")
    for switch in network.controlled_switches:
        _logger.debug(f"Configuring {switch}...")

        forwarding = switch.config.traffic_forwarding_method
        if forwarding == TrafficForwardingMethod.L3:
            _fill_l3_table(network, switch)
        elif forwarding == TrafficForwardingMethod.LABEL_BASED:
            _fill_label_based_forwarding_table(network, switch)
        else:
            raise RuntimeError(f"Unknown traffic forwarding method for {switch}: {forwarding}")


def _fill_label_based_forwarding_table(network: Network, switch: ControlledSwitch) -> None:
    """
    Fill in the tables necessary to achieve label-based forwarding:
    forward packets (from host h1) towards host h{i+2} where i is the index of the label the packet got classified as.
    Label based forwarding also works if the switch can't directly reach the destination host.
    """
    for label in Label:
        dst = f'h{label.value + 2}'
        path: List[str] = list(network.topology.get_shortest_paths_between_nodes(switch.name, dst)[0])
        next_hop: str = path[1]

        egress_intf = network.topology.edge_to_intf[switch.name][next_hop]['intfName']
        next_mac = network.topology.node_to_node_mac(next_hop, switch.name)
        leaves_network = 1 if next_hop.startswith('h') else 0  # leaves_network == next hop is a host

        _logger.debug(f'Forwarding packets classified as "{label.name}" to {next_hop} through {egress_intf}')
        action = "MyIngress.flow_action_port_forward_outside_network" if leaves_network == 1 else "MyIngress.flow_action_port_forward_within_network"
        switch.api.table_add("MyIngress.flow_action_table", [label.value],
                             action, [egress_intf, next_mac])


def _fill_l3_table(network: Network, switch: ControlledSwitch) -> None:
    """
    Fill in the next hop from the switch towards each host. This could be improved by "merging" prefixes
    and utilizing LPM (instead of using 32 as the prefix length for each entry).
    """
    for dst in sorted(network.topology.get_hosts().keys()):  # Sorting isn't necessary, it just adds determinism
        path: List[str] = list(network.topology.get_shortest_paths_between_nodes(switch.name, dst)[0])
        next_hop: str = path[1]

        dst_ip = network.topology.get_host_ip(dst)
        egress_intf = network.topology.edge_to_intf[switch.name][next_hop]['intfName']
        next_mac = network.topology.node_to_node_mac(next_hop, switch.name)
        leaves_network = 1 if next_hop.startswith('h') else 0  # leaves_network == next hop is a host

        _logger.debug(f'Registering first hop of path: {" -> ".join(path)}')
        switch.api.table_add("MyIngress.l3_forward_table", [f'{dst_ip}/32'],
                             "MyIngress.l3_forward_set", [egress_intf, next_mac, leaves_network])
