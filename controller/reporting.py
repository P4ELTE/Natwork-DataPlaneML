import logging
import threading
import time
from typing import Dict, List, Tuple

import numpy as np

from lib_common.control_plane.data import ControlledSwitch
from lib_common.data import FEATURE_STRUCT, FLOW_ID_STRUCT, REPORT_HEADER_ETHER_TYPE, REPORT_HEADER_OTHER_FIELDS_STRUCT, \
    SwitchConstants

from lib_common.flow import Feature, FeatureSchema, FlowDataCols, FlowId, FlowPredCols, Label, ListOfFeaturesSchema, \
    ListOfFlowDataSchema, \
    ListOfFlowPredSchema
from lib_common.control_plane.sniffer import PacketSniffer
from lib_common.utils import PerfReporter

_logger = logging.getLogger(__name__)


def _parse_report_packet(buffer: bytearray, length: int, interface: str) -> Tuple:
    """
    Parses the report packet and returns the parsed data.
    Used by the MonitoringAPI class, but this method is declared as a top-level function to allow pickling.
    """
    ether_type = -1 if length < 14 else buffer[12] << 8 | buffer[13]
    if ether_type != REPORT_HEADER_ETHER_TYPE:
        return interface, ether_type, None, None, None

    # We assume that the report header is present in full length in the buffer and no size checks are necessary
    buffer_offset: int = 14  # Skip the Ethernet header
    flow_id_tuple = FLOW_ID_STRUCT.unpack_from(buffer, buffer_offset)
    buffer_offset += FLOW_ID_STRUCT.size
    features_tuple = FEATURE_STRUCT.unpack_from(buffer, buffer_offset)
    buffer_offset += FEATURE_STRUCT.size
    others_tuple = REPORT_HEADER_OTHER_FIELDS_STRUCT.unpack_from(buffer, buffer_offset)
    return interface, ether_type, flow_id_tuple, features_tuple, others_tuple


class ReportingAPI:
    """
    Class responsible for 1) listening for 2) processing report packets and 3) exposing the collected data to
    higher-level components. In other words, this class implements the monitoring aspects of the controller,
    but does not make decisions based on the collected data.
    """

    def __init__(self, start_time_ms: int, switch_constants: SwitchConstants, switches: List[ControlledSwitch],
                 flow_timeout_sec: int) -> None:
        self._start_time_ms: int = start_time_ms
        self._sw_const: SwitchConstants = switch_constants
        self._switches: List[ControlledSwitch] = switches
        self._flow_timeout_sec: int = flow_timeout_sec
        self._flow_to_index: Dict[FlowId, int] = dict()
        self._flow_lock = threading.Lock()  # Lock used to synchronize access to the flow data, features and predictions
        flow_array_size = 1024  # Initial capacity of the flow arrays
        self._flow_data: ListOfFlowDataSchema = np.zeros((flow_array_size, len(FlowDataCols)),
                                                         dtype=np.uint32)
        self._flow_features: ListOfFeaturesSchema = np.zeros(
                (flow_array_size, self._sw_const.max_classifiable_flow_length,
                 len(Feature)), dtype=np.uint32)
        self._flow_pred: ListOfFlowPredSchema = np.zeros((flow_array_size, len(FlowPredCols)),
                                                         dtype=np.uint32)
        self._flow_collect_excluded: np.ndarray = np.zeros(flow_array_size, dtype=np.bool_)
        self._flow_filled_count: int = 0
        self._report_packet_sniffer: PacketSniffer = PacketSniffer(
                PerfReporter.micros(10_000, _logger, "report packet handling"))
        self._perf_ready_collect = PerfReporter.millis(1, _logger, "ready flow collection")
        self._perf_ongoing_collect = PerfReporter.millis(1, _logger, "ongoing flow collection")
        self._total_flow_count: int = 0
        self._flow_count_with_invalid_features: Tuple[int, int] = 0, 0

    def listen_for_report_packets_forever(self) -> None:
        """Starts listening for report packets without any timeout: the method blocks indefinitely."""
        interface_to_switch = {s.cpu_interface[1]: s for s in self._switches}
        _logger.info(f"Listening for report packets on interfaces: {', '.join(interface_to_switch.keys())}")

        def handle_report_packet(parsed_packet: Tuple) -> None:
            interface, ether_type, flow_id_tuple, features_tuple, others_tuple = parsed_packet
            switch = interface_to_switch[interface]

            if ether_type == -1:
                _logger.warning(f"Received packet from {switch.name} is too short: doesn't contain ethernet header")
                return
            elif ether_type != REPORT_HEADER_ETHER_TYPE:
                _logger.warning(f"Received non-report packet from {switch.name}; ether type: {ether_type}")
                return

            flow_id = FlowId.from_values(*flow_id_tuple)
            assert len(features_tuple) == len(Feature)
            features = np.asarray(features_tuple, dtype=np.uint32)
            accepted_label, latest_label, latest_label_certainty_sum, latest_label_dt_count = others_tuple
            self._update_flow_features(switch, flow_id, features, accepted_label)

        self._report_packet_sniffer.sniff_forever(list(interface_to_switch.keys()),
                                                  _parse_report_packet, handle_report_packet)

    def shutdown(self) -> None:
        """Shuts down the monitoring system, stopping the packet sniffing loop."""
        self._report_packet_sniffer.shutdown()

    @property
    def total_flow_count(self) -> int:
        """Returns the number of distinct flows that were encountered since the start of the monitoring."""
        return self._total_flow_count

    @property
    def flow_count_with_invalid_features(self) -> Tuple[int, int]:
        """
        Returns the number of flows where the count feature was detected to be invalid.
        This can happen for two reasons:
        - Report packet(s) were dropped, therefore a specific flow length didn't have any features associated with it.
          This can also mean that some crucial information got lost, e.g. when the flow got classified.
        - Hash collisions occurred in the data plane, causing a new flow to reuse a previous flow's persisted data.
        - The data plane and the controller timing out flows at a slightly different moment, causing the controller
          to expect an existing or a new flow, while the data plane provides the opposite.

        It is hard to distinguish between a hash collision and dropped report packets if both the colliding flows
        are active at the same time.

        Two values are returned:
        [0]: number of flows that started as invalid from the very first packet
        [1]: number of flows that started as valid, but became invalid later on
        """
        return self._flow_count_with_invalid_features

    @property
    def received_report_count(self) -> int:
        """Returns the number of report packets that were received since the start of the monitoring."""
        return self._report_packet_sniffer.received_packet_count

    def collect_ready_flows(self) -> Tuple[ListOfFlowDataSchema, ListOfFeaturesSchema, ListOfFlowPredSchema]:
        """
        Returns the flows that are ready for collection: flows that are either completed (no longer ongoing)
        or have reached the maximum flow length (packet count).
        For each flow, the flows' features and some general data is returned.

        Thread safety: this method is thread safe and is designed to be called periodically from a separate thread.
        """
        self._perf_ready_collect.start()
        with self._flow_lock:
            # Locate the completed flows
            current_time_ms = time.time_ns() // 1_000_000 - self._start_time_ms
            cutoff_time_ms = current_time_ms - self._flow_timeout_sec * 1000
            completed_mask = self._flow_data[:, FlowDataCols.LAST_SEEN_MS] <= cutoff_time_ms

            # Locate the flows that have reached the maximum flow length
            max_length_mask = (
                    self._flow_data[:, FlowDataCols.TOTAL_COUNT] >= self._sw_const.max_classifiable_flow_length)

            # Determine which flows can be collected and which must be kept in the array (these can overlap)
            collectible_mask = (completed_mask | max_length_mask) & ~self._flow_collect_excluded
            incomplete_mask = ~completed_mask
            # noinspection PyUnusedLocal
            completed_mask, max_length_mask = None, None  # These should not be used anymore

            # Consider that some of the entries don't have real data in them (just leftover garbage from previous flows)
            filled_mask = self._flow_data[:, FlowDataCols.TOTAL_COUNT] >= 1  # Non-empty rows in the flow data
            collectible_mask &= filled_mask
            incomplete_mask &= filled_mask

            # Copy the data and features of the collectible flows
            result = self._flow_data[collectible_mask], self._flow_features[collectible_mask], \
                self._flow_pred[collectible_mask]
            self._flow_collect_excluded[collectible_mask] = True
            # Validate that the data was copied and that the original array can be modified
            for r in result:
                assert r.base is None

            # Move the incomplete flows to the beginning of the array
            incomplete_count = np.count_nonzero(incomplete_mask)
            self._flow_data[0:incomplete_count] = self._flow_data[incomplete_mask]
            self._flow_features[0:incomplete_count] = self._flow_features[incomplete_mask]
            self._flow_pred[0:incomplete_count] = self._flow_pred[incomplete_mask]
            self._flow_collect_excluded[0:incomplete_count] = self._flow_collect_excluded[incomplete_mask]

            # Update the flow-to-index mapping
            self._flow_to_index.clear()
            for i, data_row in enumerate(self._flow_data[0:incomplete_count]):
                # noinspection PyTypeChecker
                self._flow_to_index[FlowId.from_ndarray(data_row, FlowDataCols.flow_id_begin())] = i
            self._flow_filled_count = incomplete_count

            # Clean the remaining, currently unused rows
            self._flow_data[incomplete_count:, FlowDataCols.TOTAL_COUNT] = 0  # Used to detect non-empty rows
            self._flow_collect_excluded[incomplete_count:] = False

        self._perf_ready_collect.stop()
        return result

    def collect_ongoing_flows(self) -> Tuple[ListOfFlowDataSchema, ListOfFeaturesSchema, ListOfFlowPredSchema]:
        """
        Returns the flows that are still ongoing. This method is designed to be called after collect_ready_flows.
        It returns the flows that weren't returned by the other method because they haven't timed out yet.
        For each flow, the flows' features and some general data is returned.

        Thread safety: this method is thread safe and is designed to be called periodically from a separate thread.
        """
        self._perf_ongoing_collect.start()
        with self._flow_lock:
            # We assume this method is called after collect_ready_flows, therefore each flow is an ongoing flow
            filled_mask = self._flow_data[:, FlowDataCols.TOTAL_COUNT] >= 1  # Non-empty rows in the flow data
            collectible_mask = filled_mask & ~self._flow_collect_excluded

            # Copy the data and features of the collectible flows (but don't mark them as no longer collectible)
            result = self._flow_data[collectible_mask], self._flow_features[collectible_mask], \
                self._flow_pred[collectible_mask]
            # Validate that the data was copied and that the original array can be modified
            for r in result:
                assert r.base is None

        self._perf_ongoing_collect.stop()
        return result

    def _update_flow_features(self, switch: ControlledSwitch, flow_id: FlowId,
                              features: FeatureSchema, label: int) -> None:
        """
        Appends the received features to the flow's feature series, also updating the flow metadata.
        This method also handles flows that have just started and this method also detects flows timing out.

        When implementing this method, keep in mind that multiple switches might report information about the same flow.
        In that case there is no guarantee that the packets arrive in the correct order: it is possible that the first
        packet from switch 'A' arrives when the other switch has already reported information multiple times.
        """
        count_from_packet = features[Feature.COUNT]

        with self._flow_lock:
            current_time_ms = time.time_ns() // 1_000_000 - self._start_time_ms
            cutoff_time_ms = current_time_ms - self._flow_timeout_sec * 1000

            # Get index associated with the flow
            i = self._flow_to_index.get(flow_id, None)

            # Request a new index if the flow has timed out
            if i is not None and self._flow_data[i, FlowDataCols.LAST_SEEN_MS] <= cutoff_time_ms:
                i = None

            # Ignore this data point if the maximum flow length has previously been reached
            if i is not None and count_from_packet > self._sw_const.max_classifiable_flow_length:
                self._flow_data[i, FlowDataCols.LAST_SEEN_MS] = current_time_ms  # Don't let the flow time out
                return

            # Update flow if it exists
            if i is not None:
                # Features at flow length N are stored at index N-1 (first features are stored at index 0)
                self._flow_features[i, count_from_packet - 1] = features

                # Multiple switches can report the same flow; we need to make sure that doesn't cause any issues
                old_total_count = self._flow_data[i, FlowDataCols.TOTAL_COUNT]
                # noinspection PyTypeChecker
                new_total_count = max(count_from_packet, old_total_count)
                self._flow_data[i, FlowDataCols.TOTAL_COUNT] = new_total_count

                # Detect dropped report packets and hash collisions (and out-of-sync timeouts) causing invalid features
                if new_total_count > old_total_count + 1 and not self._flow_collect_excluded[i]:
                    self._flow_collect_excluded[i] = True  # Blacklist the flow and not use its data
                    self._flow_count_with_invalid_features = self._flow_count_with_invalid_features[0], \
                        self._flow_count_with_invalid_features[1] + 1
                    _logger.debug(f"Flow {flow_id} total count increased from {old_total_count} to {new_total_count};"
                                  f" blacklisting the flow")

                self._flow_data[i, FlowDataCols.LAST_SEEN_MS] = current_time_ms
                if self._flow_pred[i, FlowPredCols.PREDICTED_LABEL] == Label.NOT_SET and label != Label.NOT_SET:
                    self._flow_pred[i, FlowPredCols.PREDICTED_LABEL] = label
                    self._flow_pred[i, FlowPredCols.PREDICTED_AT_COUNT] = count_from_packet
                return

            # Grow arrays if necessary
            if len(self._flow_data) == self._flow_filled_count:
                size = len(self._flow_data) * 2
                _logger.debug(f"Resizing flow arrays to size {size}")
                self._flow_data.resize(size, *self._flow_data.shape[1:])
                self._flow_features.resize(size, *self._flow_features.shape[1:])
                self._flow_pred.resize(size, *self._flow_pred.shape[1:])
                self._flow_collect_excluded.resize(size)

            # Insert new flow
            # _logger.debug(f"New flow: {flow_id}")  # Too verbose
            self._total_flow_count += 1
            i = self._flow_filled_count
            self._flow_filled_count += 1
            self._flow_to_index[flow_id] = i
            flow_id_begin, flow_id_end = FlowDataCols.flow_id_begin(), FlowDataCols.flow_id_end()
            self._flow_data[i, flow_id_begin:flow_id_end + 1] = flow_id.to_tuple()
            self._flow_data[i, FlowDataCols.SWITCH_ORDINAL] = switch.ordinal
            self._flow_data[i, FlowDataCols.TOTAL_COUNT] = count_from_packet
            self._flow_data[i, FlowDataCols.FIRST_SEEN_MS] = current_time_ms
            self._flow_data[i, FlowDataCols.LAST_SEEN_MS] = current_time_ms
            self._flow_features[i, 0] = features
            self._flow_pred[i, FlowPredCols.PREDICTED_LABEL] = label
            self._flow_pred[i, FlowPredCols.PREDICTED_AT_COUNT] = 1 if label != Label.NOT_SET else 0

            # Detect dropped report packets and hash collisions (and out-of-sync timeouts) causing invalid features
            if count_from_packet != 1 and not self._flow_collect_excluded[i]:
                self._flow_collect_excluded[i] = True  # Blacklist the flow and not use its data
                self._flow_count_with_invalid_features = self._flow_count_with_invalid_features[0] + 1, \
                    self._flow_count_with_invalid_features[1]
                _logger.debug(f"Flow {flow_id} reports count {count_from_packet} in the first packet;"
                              f" blacklisting the flow")
