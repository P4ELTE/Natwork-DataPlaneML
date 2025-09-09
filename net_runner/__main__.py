import hashlib
import os
import subprocess
from argparse import ArgumentParser
from pathlib import Path
from typing import List, Optional, Tuple

from mininet.log import info
from p4utils.mininetlib.network_API import NetworkAPI

import net_runner.compiler
from lib_common.data import SwitchConstants
from net_runner.net_def import CliNet, CompileNet, EvalNet, NetDefinition
from net_runner.switch import NikssSwitch
from net_runner.utils import ScheduledScript, get_nodes, schedule_script, shutdown_processes

# The available network definitions that define what exactly the network should do
net_def_choices = {'compile': CompileNet, 'cli': CliNet, 'pcap_eval': EvalNet}

# Parse arguments
parser = ArgumentParser()
parser.add_argument('--log-level', choices=['debug', 'info'], default='info')
parser.add_argument('--mode', choices=net_def_choices.keys(), default='cli')
parser.add_argument('--csv-path', type=Path, required=True,
                    help='Data source of the flow classifier oracle')
parser.add_argument('--attack-type-whitelist', type=str, default=None,
                    help="Comma-separated list of flow labels to exclusively consider as attacks")
parser.add_argument('--expected-packet-count', type=int, default=-1,
                    help='How many packets are expected to be received by controllers (or -1 if unknown)')
parser.add_argument('--eval-pcap', type=Path, default=None, help='Eval mode: PCAP file to replay')
parser.add_argument('--eval-pps', type=int, default=3500,
                    help='Eval mode: sets the packet replay rate; -1 to replay the capture in real time')
parser.add_argument('--eval-skip-packets', type=int, default=0,
                    help='Eval mode: packet count to skip at the start of the pcap file; 0 to not skip at the start')
parser.add_argument('--eval-play-sec', type=int, default=-1,
                    help='Eval mode: sets the packet replay duration in seconds; -1 to replay until the end')
parser.add_argument('--eval-save-pcap', action='store_true',
                    help='Eval mode: save the received packets to PCAP files')
parser.add_argument('--monitored-flow-ratio', type=float, required=True,
                    help='Controller config: ratio of flows to monitor (0.0 to 1.0)')
parser.add_argument('--collect-stats', action='store_true',
                    help="Controller config: whether to collect and export statistics")
parser.add_argument('--stats-database', action='store_true',
                    help="Controller config: Whether to push stats ta database (e.g. InfluxDB)")
parser.add_argument('--centralized', type=Path, default=None,
                    help="Provide a model path to use the centralized component instead of a regular controller")
args = parser.parse_args()

net = NetworkAPI()
net.setLogLevel(args.log_level)

switch_constants: SwitchConstants = SwitchConstants.create_ebpf()
switch_compiler, switch_source = net_runner.compiler.NikssCompiler, 'switch/psa/switch.p4'

if args.centralized is not None:
    switch_source = switch_source.replace('/psa/', '/psa-centralized/')

net_def: NetDefinition = net_def_choices[args.mode](switch_constants, args)

# Topology definition
topo_def = net_def.topology()
for s in topo_def.switches:
    NikssSwitch.add_to_net(net, s)
for h in topo_def.hosts:
    net.addHost(h)
for l1, l2 in topo_def.links:
    net.addLink(l1, l2)
net.setTopologyFile(f'work/topology.json')  # Topology file will be created on network startup, before scripts are ran
os.makedirs(os.path.dirname(net.topoFile), exist_ok=True)

# Host configuration
net.l3()

# Switch configuration
net.enableCpuPortAll()
net.setCompiler(switch_compiler, output_dir=f'work/switch')
net.setP4SourceAll(switch_source)

# Logging configuration
net.setLogLevel(args.log_level)
log_path = Path('work/log')
log_path.mkdir(parents=True, exist_ok=True)
net.enableLogAll(log_dir=str(log_path))

# Capturing configuration
if net_def.enable_pcap():
    net.enablePcapDumpAll(pcap_dir='work/pcap')
else:
    net.disablePcapDumpAll()

# General output directory for e.g. graphs
out_dir = Path('work/out')
out_dir.mkdir(parents=True, exist_ok=True)

# General flags shared by all Python scripts
python_flags = '-Werror -Wignore::DeprecationWarning'
python_script_flags = f'--log-level {args.log_level}'

# List of scripts scheduled to run when the network is started, in the same order as they were scheduled
scripts: List[ScheduledScript] = []

# Scripts that should have their performance evaluated, along with the output log files
perf_eval_scripts: List[Tuple[ScheduledScript, Path]] = []

if args.centralized is None:
    # Coordinator configuration
    coordinator_cmd = f'python3 {python_flags} -m coordinator {python_script_flags} {net_def.coordinator_extra_args()}'
    coordinator_script = schedule_script(net, coordinator_cmd, log_path / 'coordinator.log',
                                         'entering main loop...')

    # Oracle configuration
    csv_path: str = str(args.csv_path)
    attack_type_whitelist: Optional[str] = args.attack_type_whitelist
    oracle_cmd = (f'python3 {python_flags} -m oracle {python_script_flags} --csv-path {csv_path}'
                  f' --csv-cache-path work/cache/oracle_csv_{hashlib.md5(csv_path.encode()).hexdigest()}'
                  f' {f"--attack-type-whitelist {attack_type_whitelist}" if attack_type_whitelist is not None else ""}'
                  f' {net_def.oracle_extra_args()}')
    oracle_script = schedule_script(net, oracle_cmd, log_path / 'oracle.log',
                                    'entering main loop...')

    # Controller configuration
    controller_cmd = (f'python3 {python_flags} -m controller {python_script_flags} --topology-path {net.topoFile}'
                      f' --output-dir {out_dir} --expected-packet-count {args.expected_packet_count}'
                      f' --monitored-flow-ratio {args.monitored_flow_ratio}'
                      f' {"--collect-stats" if args.collect_stats else ""}'
                      f' {"--stats-database" if args.stats_database else ""}'
                      f' {net_def.controller_extra_args()}')
    controller_script = schedule_script(net, controller_cmd, log_path / 'controller.log',
                                        'Entering main loop...')

    scripts += [coordinator_script, oracle_script, controller_script]
    perf_eval_scripts += [(controller_script, log_path / 'perf-controller.log')]
else:  # Use different scripts if centralized component is selected
    centralized_cmd = (f'python3 {python_flags} -m centralized {python_script_flags} --topology-path {net.topoFile}'
                       f' --model-path {args.centralized} --expected-packet-count {args.expected_packet_count}')
    centralized_script = schedule_script(net, centralized_cmd, log_path / 'centralized.log',
                                         'Entering main loop...')
    scripts += [centralized_script]
    perf_eval_scripts += [(centralized_script, log_path / 'perf-centralized.log')]


# Configuration after the network is started
def configure_after_startup() -> None:
    # Set the MTU (Mininet by default tries to set a too high MTU that's not supported by BPF).
    # By setting an MTU greater than 1500 bytes, we allow some extra space for extra headers, e.g. reporting headers.
    # The interfaces on the switch side are not actually used by BPF.
    for host in get_nodes(net, include_switches=False):
        host.cmd(f"ip link set {host.name}-eth0 mtu {switch_constants.mtu}")
    net.net.get(net.cpu_bridge).cmd(f"ip link set {net.cpu_bridge} mtu {switch_constants.mtu}")
    for switch in get_nodes(net, include_hosts=False):
        if switch.name == net.cpu_bridge:
            continue
        net.net.get(net.cpu_bridge).cmd(f"ip link set {switch.name}-cpu-eth1 mtu {switch_constants.mtu}")
        for intf in (x for x in switch.intfNames() if 'eth' in x):
            switch.cmd(f"ip link set {intf} mtu {switch_constants.mtu}")


# Execution
net.disableCli()
try:
    if net_def.execute_pre_start(net):
        net.startNetwork()
        for (script, out_path) in perf_eval_scripts:
            pid = net.scripts_pids[scripts.index(script)]  # Indexes match because of the order of scheduling
            subprocess.run(f'perf stat -e task-clock,cycles,instructions -o {out_path} -p {pid} &', shell=True)
        configure_after_startup()
        for script in scripts:
            script.wait_until_ready()
        net_def.execute_post_start(net)

# Stop the network even if an exception occurs
finally:
    info('Gracefully stopping scripts...\n')
    shutdown_processes(net.scripts_pids)
    info('Stopping the network...\n')
    if net.net is not None:
        # noinspection PyUnresolvedReferences
        net.net.stop()

    for script in scripts:
        script.log_errors_warnings()
