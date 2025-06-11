import enum
import logging
import multiprocessing
import queue
import select
import socket
import time
import traceback
from typing import Callable, Dict, List, TypeVar

from lib_common.utils import PerfReporter

_logger = logging.getLogger(__name__)


class _PayloadType(enum.IntEnum):
    """Marks what kind of message was put into a message queue."""
    EXCEPTION = 0  # Signals the parent that an exception was thrown in the process
    INTERRUPT = enum.auto()  # Signals the parent that the process was interrupted
    DATA = enum.auto()  # A regular data message


T = TypeVar('T')


class PacketSniffer:
    """
    Listens for Ethernet frames on one or more network interfaces.
    Reports statistics about how many frames were captured, how long it takes to process them, etc.
    A warning is logged when the processing of frames is falling behind the reception of frames.
    """

    def __init__(self, packet_handling_perf_reporter: PerfReporter) -> None:
        self._perf_reporter: PerfReporter = packet_handling_perf_reporter
        self._mp_context: multiprocessing.context.SpawnContext = multiprocessing.get_context('spawn')
        self._shutdown_event: multiprocessing.Event = self._mp_context.Event()
        self._packet_queue: multiprocessing.Queue = self._mp_context.Queue()
        self._packet_count: int = 0
        self._shutdown = False

    def sniff_forever(self, interfaces: List[str],
                      packet_parser: Callable[[bytearray, int, str], T],
                      packet_handler: Callable[[T], None]) -> None:
        """
        Starts listening for packets without any timeout: the method blocks until shutdown is called.
        Packets are listened for on the specified interfaces, and the callbacks are called for each packet.

        The parser callback receives the packet's data buffer and the interface the packet was received on.
        This parser callback might be executed on a separate process. It must be fast (must not block), shouldn't
        hold onto the buffer and shouldn't even log for performance reasons.
        The handler callback receives the parsed packet data and is free to do whatever it wants with it.

        The parsing callback aims to reduce garbage collection overhead by reusing the buffer and putting smaller
        objects into the queue. While it might make the sniffing slower (giving more chance for packets to be dropped),
        GC pauses could also cause packet loss.
        """
        process = self._mp_context.Process(target=_sniffing_process,
                                           args=(interfaces, self._packet_queue,
                                                 self._shutdown_event, packet_parser))
        process.start()

        # Check that the process successfully started and didn't terminate immediately
        time.sleep(1)
        if process.is_alive():
            _logger.info(f"Sniffer process started on PID: {process.pid}")
            _logger.info(f"Listening on interfaces: {', '.join(interfaces)}")
        else:
            _logger.error(f"Sniffer process died immediately; queue size: {self._packet_queue.qsize()}")
            # Let the code below run: maybe the process sent an exception to the queue

        # Receive packets until a poison pill is received
        received = None
        while not self._shutdown:
            try:
                received = self._packet_queue.get(timeout=1)
                if received[0] != _PayloadType.DATA.value:
                    break
            except queue.Empty:
                continue

            with self._perf_reporter:
                self._packet_count += 1
                packet_handler(received[1])
                queue_size = self._packet_queue.qsize()
                if queue_size >= 10000 and queue_size % 5000 == 0:
                    _logger.warning(f"Packet processing is falling behind; queue size: {queue_size}")

        self._shutdown_event.set()
        _logger.debug("Receive loop has exited, checking for exceptions")
        if received is not None:
            if received[0] == _PayloadType.EXCEPTION.value:
                _logger.error("An exception was thrown in the sniffer process")
                _logger.error(received[1])
                raise Exception("An exception was thrown in the sniffer process")
            elif received[0] == _PayloadType.INTERRUPT.value:
                # We assume this is just a race condition and the shutdown flag is set at the same time
                _logger.info("Sniffer process got interrupted prior to detecting the shutdown flag, shutting down...")
            elif received[0] != _PayloadType.DATA.value:
                _logger.error(f"Unexpected message received from sniffer process: {received}")

        _logger.info(f"Sniffing finished; final received packet count: {self._packet_count}")
        # Wait for the sniffing process to finish
        process.join()
        process.close()
        _logger.debug("Sniffer process joined and closed")

    def shutdown(self) -> None:
        """Signals the packet sniffing loop to stop."""
        # We don't set the shutdown flag directly, because this method might be called from a different thread,
        # and this multiprocessing event doesn't seem to work in that case.
        self._shutdown = True
        _logger.info(f"Shutdown flag set; received until now: {self._packet_count} packets;"
                     f" still queued: {self._packet_queue.qsize()} packets")

    @property
    def received_packet_count(self) -> int:
        """Returns the number of packets received so far."""
        return self._packet_count


def _sniffing_process(interfaces: List[str], packet_queue: multiprocessing.Queue,
                      shutdown_event: multiprocessing.Event, packet_parser: Callable[[bytearray, int, str], T]) -> None:
    """Entry point of the sniffer process responsible for listening for packets on the given interfaces."""
    # noinspection PyBroadException
    try:
        _sniffing_loop(interfaces, packet_queue, shutdown_event, packet_parser)
    except KeyboardInterrupt:
        packet_queue.put((_PayloadType.INTERRUPT.value,))
    except BaseException as _:
        packet_queue.put((_PayloadType.EXCEPTION.value, traceback.format_exc()))
    packet_queue.close()
    packet_queue.join_thread()


def _sniffing_loop(interfaces: List[str], packet_queue: multiprocessing.Queue,
                   shutdown_event: multiprocessing.Event, packet_parser: Callable[[bytearray, int, str], T],
                   buffer_capacity: int = 4096) -> None:
    """Listens for packets and puts them into the packet queue until the shutdown event is set."""
    socket_to_interface: Dict[socket.socket, str] = _create_socket_to_interface_dict(interfaces)
    socket_list = list(socket_to_interface.keys())
    buffer = bytearray(buffer_capacity)

    try:
        while not shutdown_event.is_set():
            rlist, _, _ = select.select(socket_list, [], [], 1)
            for sock in rlist:
                sock: socket.socket = sock
                bytes_read = sock.recv_into(buffer, buffer_capacity)
                parsed_packet = packet_parser(buffer, bytes_read, socket_to_interface[sock])
                packet_queue.put((_PayloadType.DATA.value, parsed_packet))
    finally:
        for s in socket_list:
            s.close()


def _create_socket_to_interface_dict(interfaces: List[str]) -> Dict[socket.socket, str]:
    """Creates and initializes the sockets which can be used to listen for packets on the given interfaces."""
    sockets = dict()
    for interface in interfaces:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))  # 3 = ETH_P_ALL
        sock.bind((interface, 0))
        sockets[sock] = interface
    return sockets
