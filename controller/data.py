import dataclasses
import enum
from pathlib import Path
from typing import Dict, List, Tuple

from p4utils.utils.topology import NetworkGraph

from lib_common.data import NIKSS_PIPE_ID_OFFSET, SwitchConstants
from lib_common.model.data import ModelTrainingConfig

from p4_api_bridge import NikssCtlApiConfig, SimpleSwitchP4RuntimeApiConfig, SimpleSwitchThriftApiConfig, \
    SwitchBase, ApiBridge, ApiBridgeFactory, SwitchApiConfig, TofinoShellApiConfig


@dataclasses.dataclass(frozen=True)
class ModelRefiningConfig:
    """Configuration of how models should be improved."""
    flow_timeout_sec: int = 30  # After how many seconds of inactivity a flow is considered completed
    flow_collection_frequency_millis: int = 300  # How often to collect & classify collectible flows for re-training
    min_recent_flow_count: int = 10  # Training and performance evaluation requires at least this many "recent" flows
    training_flow_time_window_sec: int = 2700  # Last how many seconds of "recent" flows to use as training data
    scoring_flow_time_window_sec: int = 90  # Last how many seconds of "recent" flows to use for performance evaluation
    scoring_flow_age_weight_lerp_max: float = -20.0  # Newer flows get linearly more weight: oldest: *1; newest: *max
    target_latest_flow_f1_score: float = 0.99  # Re-training is not necessary above this F1 score
    acceptable_f1_score_difference: float = 0.01  # Accept new model iff: new_f1 >= min(target_f1, old_f1 + THIS)

    def __post_init__(self) -> None:
        # Sanity-check the configuration
        if self.flow_timeout_sec >= max(self.training_flow_time_window_sec, self.scoring_flow_time_window_sec):
            raise ValueError("Recent flow time windows must be greater than timeout: otherwise no flows are recent")

    @property
    def max_of_flow_time_window_sec(self) -> int:
        """The maximum of the time windows related to the recent flows."""
        return max(self.training_flow_time_window_sec, self.scoring_flow_time_window_sec)


@dataclasses.dataclass(frozen=True)
class StatsDatabaseConfig:
    """Connection parameters, configuration of the database used to store statistics."""
    hostname: str = "http://localhost:8181"
    database_name: str = "natwork-t52"
    # The database is only accessible from the internal network, so sharing the token is not a security issue
    auth_token: str = "apiv3_bOKr0cyMhOpMEyeK87IU4fuXQ-PblibC1u0ni_CXjP52fwgaaAhv5Lm8mmvQt8XyIpK521Iv4YlllmrlUtxXOA"


@dataclasses.dataclass(frozen=True)
class ControllerConfig:
    """Configuration of the controller component."""
    switch: SwitchConstants
    training: ModelTrainingConfig
    refining: ModelRefiningConfig
    stats_db: StatsDatabaseConfig
    total_monitored_flow_ratio: float  # Ratio of flows whose data and features should be collected
    oracle_endpoint: str = "tcp://localhost:52001"
    coordinator_endpoint: str = "tcp://localhost:52002"
    export_monitoring_data: bool = True  # Enable to export monitoring data to a file for offline processing


def determine_switch_constants(topology: NetworkGraph) -> SwitchConstants:
    """Determines the type of the switches in the network."""
    name, data = next(iter(topology.get_switches().items()))
    if data.get('isTofinoSwitch', False):
        return SwitchConstants.create_tofino()
    elif data.get('isNikssSwitch', False):
        return SwitchConstants.create_ebpf()
    else:
        raise RuntimeError(f"Unsupported switch type for {name}: {data}")


def determine_switch_api_types(topology: NetworkGraph) -> Dict[str, SwitchApiConfig]:
    """Determines the API type for each switch in the network."""
    result = dict()
    for name, data in topology.get_switches().items():
        default_intf_to_port = {intf: topology.interface_to_port(name, intf) for intf in
                                topology.get_interfaces(name)}

        if data.get('isTofinoSwitch', False):
            result[name] = TofinoShellApiConfig(
                    p4_program_name='natwork_t52',
                    bfsh_server_port=data['bfsh_server_port'],
                    interface_to_port=default_intf_to_port
            )
        elif data.get('isNikssSwitch', False):
            result[name] = NikssCtlApiConfig(pipeline_id=data['device_id'] + NIKSS_PIPE_ID_OFFSET)
        elif data.get('isP4RuntimeSwitch', False):
            result[name] = SimpleSwitchP4RuntimeApiConfig(
                    device_id=data['device_id'],
                    grpc_port=data['grpc_port'],
                    switch_p4rt_path=Path(data['p4rt_path']),
                    switch_json_path=Path(data['json_path']),
                    interface_to_port=default_intf_to_port
            )
        elif data.get('isThriftSwitch', False):
            result[name] = SimpleSwitchThriftApiConfig(
                    thrift_port=data['thrift_port'],
                    interface_to_port=default_intf_to_port
            )
        else:
            raise RuntimeError(f"Unknown switch type for {name}: {data}")
    return result


class TrafficForwardingMethod(enum.Enum):
    """Specifies what traffic forwarding logic a switch should use."""
    L3 = enum.auto()
    LABEL_BASED = enum.auto()


@dataclasses.dataclass(frozen=True)
class SwitchConfig:
    """Configuration of a specific switch. Different switches may have different configurations within the network."""
    switch_type: SwitchApiConfig
    traffic_forwarding_method: TrafficForwardingMethod = TrafficForwardingMethod.L3


class ControlledSwitch(SwitchBase):
    """Represents a switch within the network that is controlled by the current controller instance."""

    def __init__(self, name: str, ordinal: int, config: SwitchConfig, all_interfaces: List[str],
                 cpu_interface: Tuple[str, str], api_factory: 'ApiBridgeFactory') -> None:
        super().__init__(name, config.switch_type)
        self._ordinal: int = ordinal
        self._config: SwitchConfig = config
        self._all_interfaces: List[str] = list(all_interfaces)
        self._cpu_interface: Tuple[str, str] = cpu_interface
        self._api_factory: 'ApiBridgeFactory' = api_factory

    def __repr__(self) -> str:
        return f'Switch[{self._name}]'

    @property
    def ordinal(self) -> int:
        """The index of this switch within a list of switches."""
        return self._ordinal

    @property
    def config(self) -> SwitchConfig:
        """The configuration of this switch."""
        return self._config

    @property
    def all_interfaces(self) -> List[str]:
        """The name of all interfaces of the switch, including the CPU interface."""
        return list(self._all_interfaces)

    @property
    def cpu_interface(self) -> Tuple[str, str]:
        """
        The name of the interface that connects the switch to the controller. The first value is the name
        of the interface on the switch, the second value is the name of the interface on the controller.
        """
        return self._cpu_interface

    @property
    def api(self) -> 'ApiBridge':
        """The API through which the switch can be controlled."""
        return self._api_factory.get(self)


class ControlledSwitchFactory:
    """Responsible for creating ControlledSwitch instances."""

    def __init__(self, topology: NetworkGraph, api_factory: 'ApiBridgeFactory') -> None:
        self._topology: NetworkGraph = topology
        self._api_factory: ApiBridgeFactory = api_factory
        self._last_switch_ordinal: int = 0

    def create(self, name: str, config: SwitchConfig) -> ControlledSwitch:
        """Creates a new switch instance."""
        self._last_switch_ordinal += 1
        return ControlledSwitch(
                name=name,
                ordinal=self._last_switch_ordinal,
                config=config,
                all_interfaces=self._topology.get_interfaces(name),
                cpu_interface=self._get_cpu_interface(name),
                api_factory=self._api_factory
        )

    def _get_cpu_interface(self, switch_name: str) -> Tuple[str, str]:
        """Gets the interface names that connect the switch to the controller."""
        switch_side = self._topology.get_cpu_port_intf(switch_name)
        controller_side = self._topology.get_ctl_cpu_intf(switch_name)
        return switch_side, controller_side


class Network:
    """Represents a computer network. Some switches in the network are controlled by the current controller instance."""

    def __init__(self, topology: NetworkGraph, controlled_switches: List[ControlledSwitch]) -> None:
        self._topology: NetworkGraph = topology
        self._controlled_switches: List[ControlledSwitch] = list(controlled_switches)

    @property
    def topology(self) -> NetworkGraph:
        """The topology of the entire network. Includes elements (e.g. switches) not managed by this controller."""
        # Future work: don't depend directly on the NetworkGraph class
        return self._topology

    @property
    def controlled_switches(self) -> List[ControlledSwitch]:
        """The switches within the network that are controlled by this controller."""
        return list(self._controlled_switches)
