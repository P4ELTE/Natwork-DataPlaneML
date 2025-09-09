import argparse
import json
import logging
import sys
import time
from typing import Optional

import joblib
import networkx
from p4_api_bridge import ApiBridgeFactory
from p4utils.utils.topology import NetworkGraph

from centralized.logic import CentralizedLogic
from lib_common.control_plane.data import ControlledSwitchFactory, Network, SwitchConfig, TrafficForwardingMethod, \
    determine_switch_api_types, \
    determine_switch_constants
from lib_common.model.data import Model, ModelTrainingConfig
from lib_common.utils import handle_sigterm_sigint

_logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', choices=['debug', 'info'], default='info')
    parser.add_argument('--topology-path', type=argparse.FileType(), required=True,
                        help="Path to the JSON file defining the topology of the entire network")
    parser.add_argument('--model-path', type=argparse.FileType('rb'), required=True,
                        help="The pre-trained model to use for classification")
    parser.add_argument('--flow-timeout-sec', type=int, default=30,
                        help='After how many seconds a flow should be considered done if no packets are received')
    parser.add_argument('--expected-packet-count', type=int, default=-1,
                        help='How many packets are expected to be received (or -1 if unknown)')
    args = parser.parse_args()

    logging.basicConfig(force=True, level=args.log_level.upper(),
                        format='[%(asctime)s] %(levelname)s [%(threadName)s] [%(name)s] %(message)s',
                        stream=sys.stdout)
    logging.getLogger("matplotlib").setLevel(logging.INFO)

    # We don't use p4utils.utils.helper.load_topo because it imports mininet logging, which screws up the logging module
    with args.topology_path as f:
        try:
            topology = NetworkGraph(networkx.node_link_graph(json.load(f), edges="links"))
        except TypeError:
            f.seek(0)
            topology = NetworkGraph(networkx.node_link_graph(json.load(f)))

    with args.model_path as f:
        model: Model = joblib.load(f)

    expected_packet_count = args.expected_packet_count
    if expected_packet_count < 0:
        expected_packet_count = None

    start_centralized(topology, model, args.flow_timeout_sec, expected_packet_count)


def start_centralized(topology: NetworkGraph, model: Model, flow_timeout_sec: int,
                      expected_packet_count: Optional[int]) -> None:
    _logger.info(f"Using a topology consisting of {len(topology.get_switches())} switches"
                 f" and {len(topology.get_hosts())} hosts")
    _logger.info(f"The model consists of {len(model.id_to_rf)} random forests")

    switch_constants = determine_switch_constants(topology)
    switch_to_api_type = determine_switch_api_types(topology)
    controlled_switches = {s: SwitchConfig(
            switch_type=switch_to_api_type[s],
            traffic_forwarding_method=TrafficForwardingMethod.LABEL_BASED
    ) for s in topology.get_switches().keys()}

    api_bridge_factory = ApiBridgeFactory()
    controlled_switch_factory = ControlledSwitchFactory(topology, api_bridge_factory)
    network = Network(topology, [controlled_switch_factory.create(s, c) for s, c in controlled_switches.items()])

    _logger.info('Basic initialization done, executing logic')
    start_time_ms = time.time_ns() // 1_000_000  # Used as an offset to make timestamps fit into 32 bits
    logic = CentralizedLogic(start_time_ms, network, model, switch_constants,
                             ModelTrainingConfig.create_for_centralized(),
                             flow_timeout_sec, expected_packet_count)

    logic.initialize_switches()
    handle_sigterm_sigint(lambda: logic.shutdown())
    logic.run_main_loop()
    _logger.info("Main loop has exited, cleaning up...")
    for switch in network.controlled_switches:
        switch.api.close()


if __name__ == '__main__':
    main()
