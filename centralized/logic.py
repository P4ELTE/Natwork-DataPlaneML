import logging
import socket
import time
from typing import Optional, Tuple

import dpkt
import numpy as np

from centralized.storage import FlowSingleLengthStorage
from lib_common import feature_extraction
from lib_common.control_plane import traffic_forwarding
from lib_common.control_plane.data import ControlledSwitch, Network
from lib_common.control_plane.sniffer import PacketSniffer
from lib_common.data import SwitchConstants
from lib_common.flow import Feature, FeatureSchema, FlowId, Label
from lib_common.model.data import Model, ModelTrainingConfig
from lib_common.utils import PerfReporter

_logger = logging.getLogger(__name__)


ETHER_TYPE_CUSTOM = 0x1236  # Custom ether type of our custom "classified" packets


class CentralizedLogic:
    """Main logic of the centralized controller."""

    def __init__(self, start_time_ms: int, network: Network, model: Model,
                 switch_constants: SwitchConstants, training_config: ModelTrainingConfig,
                 flow_timeout_sec: int, expected_packet_count: Optional[int]) -> None:
        self._shutdown: bool = False
        self._start_time_ms: int = start_time_ms
        self._network: Network = network
        self._model: Model = model
        self._switch_constants: SwitchConstants = switch_constants
        self._training_config: ModelTrainingConfig = training_config
        self._expected_packet_count: Optional[int] = expected_packet_count
        self._sniffer: PacketSniffer = PacketSniffer(
                PerfReporter.micros(10_000, _logger, "packet handling"))
        self._storage: FlowSingleLengthStorage = FlowSingleLengthStorage(start_time_ms, flow_timeout_sec)

        self._switch_sender: ControlledSwitch = self._network.controlled_switches[0]
        self._switch_receiver: ControlledSwitch = self._network.controlled_switches[-1]
        _logger.info(f"Switch sending packets to the controller for classification: {self._switch_sender.name}")
        _logger.info(f"Switch receiving classified packets from the controller: {self._switch_receiver.name}")

    def initialize_switches(self) -> None:
        """Initializes the switches prior to entering the main loop."""
        _logger.info("Initializing switches...")
        # We only create the multicast group on the sender switch -> other switches will fail to send us packets
        traffic_forwarding.create_cpu_port_multicast([self._switch_sender], 42)
        traffic_forwarding.configure_forwarding(self._network)

    def shutdown(self) -> None:
        """Signals the logic to shut down."""
        if self._shutdown:
            return

        _logger.info("Shutting down...")
        self._shutdown = True
        self._sniffer.shutdown()

        # Log approximately how many packets got dropped
        if self._expected_packet_count is not None:
            actual, expected = self._sniffer.received_packet_count, self._expected_packet_count
            _logger.warning(f"Packet counts:"
                            f" expected={expected}; actual={actual};"
                            f" diff={abs(expected - actual)} ({100 * abs(expected - actual) / expected:.2f}%)")

        # Log how many flows got classified as what
        _logger.info("Flow classification statistics:")
        label_counts = self._storage.get_label_counts()
        total_count = sum(label_counts.values())
        if total_count > 0:
            for label, count in label_counts.items():
                _logger.info(f"Label {label.name}: {count} ({100 * count / total_count:.2f}%)")
        else:
            _logger.info("No flows were classified, all counts are zero")

    def run_main_loop(self) -> None:
        """Runs the main loop of the logic."""
        _logger.info("Entering main loop...")
        tmp_buffer = bytearray(self._switch_constants.mtu + 3)  # Fits the original packet and the extra header

        out_sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
        out_sock.bind((self._switch_receiver.cpu_interface[1], 0))

        def handle_packet(parsed_packet: Tuple) -> None:
            intf, original_packet, rest_packet = parsed_packet
            if rest_packet is None:
                _logger.warning(f"Received a non-IP packet from {intf}, ether type: {original_packet}")
                return

            flow_id: FlowId = rest_packet[0]
            features: FeatureSchema = rest_packet[1]
            new_timestamp: int = rest_packet[2] - self._start_time_ms  # Convert to milliseconds since start

            # Update flow features
            stored_data = self._storage.get_stored(flow_id, new_timestamp)
            if stored_data is None:
                stored_features, label = features, Label.NOT_SET
                self._storage.insert(flow_id, stored_features, new_timestamp)
            else:
                last_timestamp, stored_features, label = stored_data
                feature_extraction.merge_features(stored_features, last_timestamp, features, new_timestamp)

            # Classify the flow if not already classified
            if label == Label.NOT_SET:
                flow_length = int(stored_features[Feature.COUNT])
                label = self._execute_inference(flow_length, features)
                if label != Label.NOT_SET:
                    self._storage.set_label(flow_id, label)

            self._handle_packet_based_on_label(tmp_buffer, original_packet, out_sock, label)

        self._sniffer.sniff_forever([self._switch_sender.cpu_interface[1]], _parse_packet, handle_packet)

        out_sock.close()

    def _execute_inference(self, flow_length: int, features: FeatureSchema) -> Label:
        """Executes inference using the model, returning the assigned label, if inference was successful."""
        rf = self._model.id_to_rf.get(self._model.flow_length_to_id.get(flow_length, None), None)
        if rf is None:
            return Label.NOT_SET  # Classification not possible at this flow length by this model

        certainties = rf.classifier.predict_proba(np.reshape(features, (1, -1)))
        if np.max(certainties) >= self._training_config.classification_certainty_threshold:
            return Label(rf.classifier.classes_[np.argmax(certainties)])
        else:
            return Label.NOT_SET  # Flow should be classified at a later flow length instead

    def _handle_packet_based_on_label(self, tmp_buffer: bytearray, original_packet: bytearray,
                                      sock: socket.socket, label: Label) -> None:
        # Overwrite the ether type to the custom header's type
        tmp_buffer[0:12] = original_packet[0:12]  # Copy MAC addresses
        tmp_buffer[12] = ETHER_TYPE_CUSTOM >> 8
        tmp_buffer[13] = ETHER_TYPE_CUSTOM & 0xFF
        length = 14

        # Add the custom header: ether type field
        tmp_buffer[length] = original_packet[12]
        tmp_buffer[length + 1] = original_packet[13]
        length += 2

        # Add the custom header: label field
        tmp_buffer[length] = label.value
        length += 1

        # Add the rest of the original packet
        tmp_buffer[length:length + len(original_packet)] = original_packet
        length += len(original_packet)

        to_send = memoryview(tmp_buffer)[:length]
        sock.send(to_send)


def _parse_packet(buffer: bytearray, length: int, interface: str) -> Optional[Tuple]:
    """
    Parses the packet and returns the parsed data.
    This method is declared as a top-level function to allow pickling.
    """
    ether_type = -1 if length < 14 else buffer[12] << 8 | buffer[13]
    if ether_type == ETHER_TYPE_CUSTOM:
        # Ignore packet if it's our own custom packet. Reason: we may receive packets that
        # we sent ourselves, if self._switch_sender and self._switch_receiver are the same switch.
        # See: https://www.linuxquestions.org/questions/programming-9/raw-receive-socket-also-delivers-sent-frames-640568/
        #   (Checking pkttype from the addr did not work, pkttype was always BROADCAST)
        return None
    if ether_type != 0x0800:  # not IPv4
        return interface, ether_type, None
    else:
        original_packet = bytearray(buffer[:length])
        eth = dpkt.ethernet.Ethernet(buffer)
        ip = eth.data
        flow_id = FlowId.from_dpkt_packet(ip)
        features = feature_extraction.parse_packet(ip)
        timestamp = time.time_ns() // 1_000_000
        return interface, original_packet, (flow_id, features, timestamp)
