import argparse
import json
import logging
import os
import sys
import threading
import time
from pathlib import Path
from typing import Callable, List, Optional

import joblib
import networkx
from p4utils.utils.topology import NetworkGraph

from controller.data import ControllerConfig, ModelRefiningConfig, StatsDatabaseConfig
from controller.interface import ZmqCoordinatorInterface, ZmqOracleInterface
from controller.logic import ControllerLogic
from controller.stats import Influxdb3StatsManager, MatplotlibStatsManager, StatsManager, StatsManagerContainer
from lib_common.control_plane.data import ControlledSwitchFactory, Network, SwitchConfig, TrafficForwardingMethod, \
    determine_switch_api_types, \
    determine_switch_constants
from lib_common.model.data import Model, ModelTrainingConfig
from lib_common.utils import handle_sigterm_sigint
from p4_api_bridge import ApiBridgeFactory

_logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', choices=['debug', 'info'], default='info')
    parser.add_argument('--controller-id', type=str, default='Controller-ONLY',
                        help="The short, unique identifier of this network domain/controller")
    parser.add_argument('--topology-path', type=argparse.FileType(), required=True,
                        help="Path to the JSON file defining the topology of the entire network")
    parser.add_argument('--model-path', type=argparse.FileType('rb'), default=None,
                        help="A pre-trained model can be loaded at startup by providing the path of the binary file")
    parser.add_argument('--output-dir', type=Path, required=True,
                        help="Folder where the graphs and other output files should be saved")
    parser.add_argument('--label-based-forwarding', action='store_true',
                        help="Forward packets based on their assigned label instead of the destination IP address")
    parser.add_argument('--expected-packet-count', type=int, default=-1,
                        help='How many packets are expected to be received (or -1 if unknown)')
    parser.add_argument('--monitored-flow-ratio', type=float, required=True,
                        help='Controller config: ratio of flows to monitor (0.0 to 1.0)')
    parser.add_argument('--collect-stats', action='store_true',
                        help="Controller config: Whether to collect and export statistics")
    parser.add_argument('--stats-database', action='store_true',
                        help="Controller config: Whether to push stats ta database (e.g. InfluxDB)")
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

    model = Model(flow_length_to_id=dict(), id_to_rf=dict())  # Empty model, classifies nothing
    if args.model_path is not None:
        with args.model_path as f:
            model: Model = joblib.load(f)

    # We keep everything at its default value for now
    switch_constants = determine_switch_constants(topology)
    config = ControllerConfig(
            switch=switch_constants,
            training=ModelTrainingConfig.create_for_switch(switch_constants),
            refining=ModelRefiningConfig(),
            stats_db=StatsDatabaseConfig() if args.stats_database else None,
            monitored_flow_ratio=args.monitored_flow_ratio,
            stats_from_all_flows=args.collect_stats
    )

    forwarding_method = TrafficForwardingMethod.L3
    if args.label_based_forwarding:
        forwarding_method = TrafficForwardingMethod.LABEL_BASED

    expected_packet_count = args.expected_packet_count
    if expected_packet_count < 0:
        expected_packet_count = None

    output_dir = args.output_dir / args.controller_id
    output_dir.mkdir(parents=True, exist_ok=True)
    start_controller(args.controller_id, config, topology, model, output_dir, forwarding_method,
                     expected_packet_count)


def start_controller(controller_id: str, config: ControllerConfig, topology: NetworkGraph, model: Model,
                     output_dir: Path, forwarding_method: TrafficForwardingMethod,
                     expected_packet_count: Optional[int]) -> None:
    _logger.info(f"This instance is named '{controller_id}'; PID: {os.getpid()}")
    _logger.info(f"Using the following configuration: {config}")
    _logger.info(f"Using a topology consisting of {len(topology.get_switches())} switches"
                 f" and {len(topology.get_hosts())} hosts")
    _logger.info(f"The initial model consists of {len(model.id_to_rf)} random forests")
    _logger.info(f"Using the following traffic forwarding method: {forwarding_method}")

    switch_to_api_type = determine_switch_api_types(topology)
    controlled_switches = {s: SwitchConfig(
            switch_type=switch_to_api_type[s],
            traffic_forwarding_method=forwarding_method
    ) for s in topology.get_switches().keys()}

    api_bridge_factory = ApiBridgeFactory()
    controlled_switch_factory = ControlledSwitchFactory(topology, api_bridge_factory)
    network = Network(topology, [controlled_switch_factory.create(s, c) for s, c in controlled_switches.items()])

    oracle_interface = ZmqOracleInterface(config.oracle_endpoint)
    coordinator_interface = ZmqCoordinatorInterface(config.coordinator_endpoint, controller_id)

    start_time_ms = time.time_ns() // 1_000_000  # Used as an offset to make timestamps fit into 32 bits
    stat_managers: List[StatsManager] = []
    if config.stats_from_all_flows:
        stat_managers.append(MatplotlibStatsManager(start_time_ms, config))
        if config.stats_db is not None:
            stat_managers.append(Influxdb3StatsManager(start_time_ms, config, controller_id))
    stats: StatsManager = StatsManagerContainer(start_time_ms, config, stat_managers)

    logic = ControllerLogic(start_time_ms, output_dir, config, network,
                            oracle_interface, coordinator_interface, model, stats, expected_packet_count)

    _logger.info('Basic data have been prepared; starting controller logic')
    logic.initialize_switches()
    monitoring_listener_thread = start_thread(name="MonitoringListener", target=logic.run_monitoring_listener_loop)
    try:
        handle_sigterm_sigint(lambda: logic.shutdown())
        logic.run_main_loop()
        monitoring_listener_thread.join(timeout=30)
    finally:
        for switch in network.controlled_switches:
            switch.api.close()
        _logger.info("Main loop has exited, saving statistics graph...")
        stats.finished()
        stats.export(output_dir / 'stats.pickle')
        stats.visualize(output_dir, f'stats')
        _logger.info("Statistics have been saved")


def start_thread(name: str, target: Callable) -> threading.Thread:
    def _target_wrapper() -> None:
        try:
            _logger.info(f"Thread starting: {name}")
            target()
        finally:
            _logger.info(f"Thread ending: {name}")

    thread = threading.Thread(name=name, target=_target_wrapper, daemon=False)
    thread.start()
    return thread


if __name__ == '__main__':
    main()
