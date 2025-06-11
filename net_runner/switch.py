import os.path
from typing import List, Tuple, Optional

from mininet.link import Intf
from mininet.log import output, info, debug, error, warn
from mininet.node import Switch
from p4utils.mininetlib.network_API import NetworkAPI

from lib_common.data import NIKSS_PIPE_ID_OFFSET


class NikssSwitch(Switch):
    """NIKSS switch controlled via nikss-ctl. The switch is considered a P4Switch, even though it's not its subclass."""

    _next_free_device_id: int = 1

    @staticmethod
    def add_to_net(net: NetworkAPI, name: str):
        """Utility method for adding a single NIKSS switch to a network."""
        device_id = NikssSwitch._next_free_device_id
        NikssSwitch._next_free_device_id += 1
        net.addP4Switch(name, cls=NikssSwitch, device_id=device_id, isNikssSwitch=True)

    def __init__(self, name, device_id, json_path=None, pcap_dump=False, pcap_dir='/tmp',
                 log_enabled=False, log_dir='/tmp', **kwargs) -> None:
        super().__init__(name, str(device_id), **kwargs)
        self._running: bool = False
        self._pipe_id: int = device_id + NIKSS_PIPE_ID_OFFSET
        self._ebpf_program: str = json_path

        self._pcap_dir: Optional[str] = None
        if pcap_dump:
            os.makedirs(pcap_dir, exist_ok=True)
            self._pcap_dir = pcap_dir
            error("Mininet NIKSS switches don't support packet captures (yet)\n")

        self._log_redirect: str = '> /dev/null 2>&1'
        if log_enabled:
            os.makedirs(log_dir, exist_ok=True)
            log_file = f'{log_dir}/{name}.log'
            self._log_cmd(f'echo > {log_file}')  # Clear or create log file
            self._log_redirect: str = f'>> {log_file} 2>&1'
            error("Mininet NIKSS switches don't (yet) log anything while they are running\n")

    def switch_running(self) -> bool:
        return self._running

    # noinspection PyUnusedLocal
    def start(self, controllers: List = None) -> None:
        self._running = True
        info(f"Starting NIKSS switch {self.name}\n")

        if self._log_cmd(f"nikss-ctl validate-os") != 0:
            error("Invalid system or namespace configuration, NIKSS will not work (check logs for more info)\n")
            raise RuntimeError

        if self._log_cmd(f"nikss-ctl pipeline show id {self._pipe_id}") == 0:
            error(f"Pipeline {self._pipe_id} is already loaded, aborting.\n")
            error(f"You can unload it manually via 'nikss-ctl pipeline unload id {self._pipe_id}'\n")
            raise RuntimeError

        if self._log_cmd(f"nikss-ctl pipeline load id {self._pipe_id} {self._ebpf_program}") != 0:
            error("Unable to load pipeline, aborting (check logs for more info)\n")
            raise RuntimeError

        for port, interface in self._relevant_interfaces():
            debug(f"Attaching port {interface}\n")
            if self._log_cmd(f"nikss-ctl add-port pipe {self._pipe_id} dev {interface}") != 0:
                error("Unable to attach port, aborting (check logs for more info)\n")
                raise RuntimeError

    # noinspection PyPep8Naming
    def stop(self, deleteIntfs: bool = True) -> None:
        self._running = False
        info(f"Stopping NIKSS switch {self.name}\n")

        for port, interface in self._relevant_interfaces():
            debug(f"Detaching port {interface}\n")
            self._log_cmd(f"nikss-ctl del-port pipe {self._pipe_id} dev {interface}")

        if self._log_cmd(f"nikss-ctl pipeline unload id {self._pipe_id}") != 0:
            warn("Unable to unload pipeline, please check logs\n")

        super().stop(deleteIntfs)

    def describe(self) -> None:
        output(f"{self.name} -> pipeline id: {self._pipe_id}\n")

    def _log_cmd(self, cmd: str) -> int:
        escaped_cmd = cmd.replace("\"", "\\\"")
        self.cmd(f'echo "$ {escaped_cmd}" {self._log_redirect}', shell=True)
        self.cmd(cmd + " " + self._log_redirect, shell=True)
        return int(self.cmd(f'echo $?', shell=True))

    def _relevant_interfaces(self) -> List[Tuple[int, Intf]]:
        return [(port, intf) for port, intf in self.intfs.items() if not intf.IP()]
