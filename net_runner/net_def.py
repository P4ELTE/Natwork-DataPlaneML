import abc
import dataclasses
import logging
import math
import re
import time
from argparse import Namespace
from pathlib import Path
from typing import List, Tuple

from mininet.log import info, error
from p4utils.mininetlib.network_API import NetworkAPI

from lib_common.data import SwitchConstants
from lib_common.flow import Label

_logger = logging.getLogger(__name__)


@dataclasses.dataclass
class TopologyDefinition:
    switches: List[str]
    hosts: List[str]
    links: List[Tuple[str, str]]


class NetDefinition(abc.ABC):
    """Base class for network definitions."""

    def __init__(self, switch_constants: SwitchConstants, args: Namespace):
        self._sw_const = switch_constants
        self._args = args

    @abc.abstractmethod
    def topology(self) -> TopologyDefinition:
        """Defines the desired topology of the network."""

    def coordinator_extra_args(self) -> str:
        """
        Defines what extra arguments the coordinator script should be invoked with.
        Many parameters are automatically passed, no need to include e.g. the log level here.
        """
        return ''

    def oracle_extra_args(self) -> str:
        """
        Defines what extra arguments the oracle script should be invoked with.
        Many parameters are automatically passed, no need to include e.g. the log level here.
        """
        return ''

    def controller_extra_args(self) -> str:
        """
        Defines what extra arguments the controller script should be invoked with.
        Many parameters are automatically passed, no need to include e.g. the log level here.
        """
        return ''

    def enable_pcap(self) -> bool:
        """Whether packet capturing should be enabled for the network."""
        return False

    @abc.abstractmethod
    def execute_pre_start(self, net: NetworkAPI) -> bool:
        """Prepares the network for execution. This method is called before the network is started.
        Returns whether the network should be started."""

    @abc.abstractmethod
    def execute_post_start(self, net: NetworkAPI) -> None:
        """Does something with the running network, e.g. starting the Mininet simulation and a CLI."""


class CompileNet(NetDefinition):
    def __init__(self, switch_constants: SwitchConstants, args: Namespace):
        super().__init__(switch_constants, args)

    def topology(self) -> TopologyDefinition:
        return TopologyDefinition(['s1'], [], [])

    def execute_pre_start(self, net: NetworkAPI) -> bool:
        net.compile()
        return False

    def execute_post_start(self, net: NetworkAPI) -> None:
        raise AssertionError("This method should not be called")


class CliNet(NetDefinition):
    def __init__(self, switch_constants: SwitchConstants, args: Namespace):
        super().__init__(switch_constants, args)

    def topology(self) -> TopologyDefinition:
        switches = ['s1']
        hosts, links = [], []
        for i in [1, 2]:
            hosts.append(f'h{i}')
            links.append(('s1', f'h{i}'))
        return TopologyDefinition(switches, hosts, links)

    def execute_pre_start(self, net: NetworkAPI) -> bool:
        return True

    def execute_post_start(self, net: NetworkAPI) -> None:
        net.start_net_cli()


class EvalNet(NetDefinition):
    def __init__(self, switch_constants: SwitchConstants, args: Namespace):
        super().__init__(switch_constants, args)
        self._pcap_path: Path = args.eval_pcap
        if not self._pcap_path or not self._pcap_path.exists():
            raise ValueError(f'Invalid pcap file: {self._pcap_path}')
        self._replay_pps: int = args.eval_pps
        self._replay_skip_packets: int = args.eval_skip_packets
        self._replay_play_sec: int = args.eval_play_sec
        self._save_pcap: bool = args.eval_save_pcap
        self._tcpreplay_cmd: str = ""  # The entire tcpreplay command that should be executed

        # One hosts sends the packets that should be classified
        self._sender_host = 'h1'
        info(f"Host sending the packets to be classified: {self._sender_host}\n")

        # Switch chain: sender host -> s1 -> ... -> sN -> one of the label hosts
        # There are as many switches as necessary to execute each DT once
        switch_count = math.ceil(switch_constants.dt_per_rf_count / switch_constants.dt_per_switch_count)
        self._switch_chain = [f's{i + 1}' for i in range(switch_count)]
        info(f"Switch chain executing the inference: {self._switch_chain}\n")

        # One host for each label (receivers)
        self._label_hosts = []
        for label in Label:
            host = f'h{label.value + 2}'  # h0 is reserved and h1 is the sender -> offset by 2
            self._label_hosts.append(host)
            info(f"Host receiving packets classified as label '{label}': {host}\n")

    def topology(self) -> TopologyDefinition:
        links = [('s1', self._sender_host)]
        links += [(self._switch_chain[i - 1], self._switch_chain[i]) for i in range(1, len(self._switch_chain))]
        links += [(self._switch_chain[-1], host) for host in self._label_hosts]
        return TopologyDefinition(self._switch_chain, [self._sender_host, *self._label_hosts], links)

    def controller_extra_args(self) -> str:
        return '--label-based-forwarding'

    def enable_pcap(self) -> bool:
        # Enabling automatic packet capture is not needed/ideal:
        # - it would capture packets on all interfaces in both directions
        # - it is not yet supported by NIKSS switches
        return False

    def execute_pre_start(self, net: NetworkAPI) -> bool:
        # Start packet capture on label hosts
        if self._save_pcap:
            Path("work/pcap").mkdir(exist_ok=True)
            for host in self._label_hosts:
                cmd = f"tcpdump -i {host}-eth0 --direction=in -w work/pcap/{host}-in.pcap"
                # bash -c is necessary for logging to work with Mininet tasks
                net.addTask(host, f"bash -c '{cmd} > {self._host_to_log_file(host)} 2>&1'")

        replay_args = ""
        if self._replay_pps == -1:
            info("Replaying pcap at the rate it was captured (1x speed)\n")
        else:
            info(f"Ignoring original packet timestamps and replaying at {self._replay_pps} pps.\n")
            info("  This should only be done when time-based features weren't used to train the RFs.\n")
            replay_args += f" --pps={self._replay_pps}"

        info(f"Replaying PCAP from the {self._replay_skip_packets + 1}. packet "
             f"{'until the end' if self._replay_play_sec == -1 else f'for {self._replay_play_sec} seconds'}\n")
        if self._replay_play_sec != -1:
            replay_args += f" --duration={self._replay_play_sec}"

        # Some datasets use a very high MTU, which might not be supported by e.g. BPF.
        # For this reason, we truncate packets to a lower MTU, leaving enough space for extra headers we might add.
        # For some reason, values greater than ~1800 bytes cause packet loss. We use 1600 to be safe.
        skip_arg = "" if self._replay_skip_packets == 0 else f"1-{self._replay_skip_packets}"
        self._tcpreplay_cmd = (f"editcap -F pcap {self._pcap_path} - {skip_arg} |"
                               f" tcpreplay-edit --mtu={1600} --mtu-trunc --no-flow-stats"
                               f" -i {self._sender_host}-eth0 {replay_args} -"
                               f" > {self._host_to_log_file(self._sender_host)} 2>&1")
        return True

    def execute_post_start(self, net: NetworkAPI) -> None:
        # Create lock file to indicate that the evaluation is active
        lock_file = Path("work/eval-active.lock")
        lock_file.touch()
        lock_file.chmod(0o666)

        # Start packet replay on sender host, without waiting for it (delay a bit to ensure packet capturing is ready)
        net.net.get(self._sender_host).cmd(f"bash -c 'sleep 3 ; {self._tcpreplay_cmd} ; rm {lock_file}' &")

        # Wait for tcpreplay to finish
        start_time, last_print = time.time(), 0
        while lock_file.exists():
            if time.time() - last_print >= 30:
                last_print = time.time()
                elapsed_time = time.strftime('%H:%M:%S', time.gmtime(time.time() - start_time))
                info(f"Waiting for packet replaying to finish... (Elapsed time: {elapsed_time})\n")
            time.sleep(5)

        # Determine whether sending packets was successful (only available if tcpdump was running)
        if self._save_pcap:
            with open(self._host_to_log_file(self._sender_host)) as f:
                for line in f:
                    if matcher := re.match(r'^\s*Failed packets:\s*(\d+)$', line):
                        if int(matcher.group(1)) == 0:
                            break
                        else:
                            error("Packet replaying failed: there were failed packet(s)\n")
                            raise RuntimeError(f"Error occurred during packet replaying, see log files for details")
                else:
                    raise RuntimeError("Unable to determine the result of packet replaying")
        info("Packet replaying finished successfully: 0 reported failed packets\n")
        info("Waiting 60 seconds for the last packets to be processed and the flows to time out...\n")
        time.sleep(60)

    def _host_to_log_file(self, host: str) -> str:
        return f'work/log/{host}.log'
