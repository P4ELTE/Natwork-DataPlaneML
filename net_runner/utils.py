import dataclasses
import signal
import time
from pathlib import Path
from typing import List

import psutil
from mininet.log import info, warning
from mininet.node import Node
from p4utils.mininetlib.network_API import NetworkAPI


@dataclasses.dataclass(frozen=True)
class ScheduledScript:
    """Holds information about a scheduled script."""
    cmd: str
    out_file: Path
    ready_text: str

    def _wait_until_text(self, text: str, timeout_sec: int = 30) -> None:
        """Waits until the script has written the given text to the output file (or a timeout happens)."""
        info(f'Waiting for "{text}" to appear in {self.out_file}...\n')
        start_time = time.time()
        # noinspection PyTypeChecker
        while time.time() - start_time < timeout_sec:
            try:
                with self.out_file.open('r') as f:
                    for line in f:  # Check line-by-line for performance reasons
                        if text in line:
                            info(f'Found "{text}" in {self.out_file}\n')
                            return  # Text found
            except FileNotFoundError:
                pass  # File is yet to be created
            time.sleep(0.5)
        raise TimeoutError(f'Timed out waiting for "{text}" to appear in {self.out_file}')

    def wait_until_ready(self, timeout_sec: int = 60) -> None:
        """Waits until the script has written the ready text to the output file (or a timeout happens)."""
        self._wait_until_text(self.ready_text, timeout_sec)

    def log_errors_warnings(self) -> None:
        """Logs the errors and warnings that the script has written to the output file."""
        strings = [' ERROR ', ' WARNING ', ' FATAL ', 'Traceback ']
        try:
            any_found = False
            with self.out_file.open('r') as f:
                for line in f:
                    for s in strings:
                        if s in line:
                            if not any_found:
                                warning(f'Errors/warnings in {self.out_file}:\n')
                                any_found = True
                            warning(f'{line.strip()}\n')
        except FileNotFoundError:
            pass


def schedule_script(net: NetworkAPI, cmd: str, out_file: Path, ready_text: str) -> ScheduledScript:
    """Schedules a script to be executed when the network is started."""
    net.execScript(cmd, out_file=str(out_file))
    return ScheduledScript(cmd, out_file, ready_text)


def get_nodes(net: NetworkAPI, include_switches: bool = True, include_hosts: bool = True) -> List[Node]:
    """Gets the nodes (hosts and/or switches) in the network."""
    result = []
    if include_hosts:
        # noinspection PyUnresolvedReferences
        result += [net.net.get(x) for x in net.hosts()]
    if include_switches:
        # noinspection PyUnresolvedReferences
        result += [net.net.get(x) for x in net.switches()]
    return result


def shutdown_processes(pids: List[int], graceful_stop_timeout: int = 120) -> None:
    """
    Gracefully shuts down the processes with the given PIDs and their children (via SIGTERM).
    If the processes do not stop within the configurable timeout, they are forcefully killed (via SIGKILL).
    """
    processes = []
    for pid in pids:
        proc = psutil.Process(pid)
        processes.append(proc)
        processes += proc.children(recursive=True)

    # Graceful shutdown
    for proc in processes:
        try:
            proc.send_signal(signal.SIGTERM)
        except psutil.NoSuchProcess:
            warning(f'Process pid={proc.pid} does not exist\n')

    # Wait for processes to shut down, get the processes that did not stop
    _, processes = psutil.wait_procs(processes, timeout=graceful_stop_timeout)

    # Forceful shutdown
    for proc in processes:
        warning(f'Process pid={proc.pid} did not stop gracefully, killing it...\n')
        try:
            proc.send_signal(signal.SIGKILL)
        except psutil.NoSuchProcess:
            pass
