import dataclasses
import logging
import time
from typing import Dict, Optional, Tuple

import numpy as np

from lib_common.flow import Feature, FeatureSchema, FlowDataCols, FlowId, FlowPredCols, Label, \
    ListOfFeaturesSchema, \
    ListOfFlowDataSchema, ListOfFlowPredSchema

_logger = logging.getLogger(__name__)


class FlowSingleLengthStorage:
    """
    Class responsible for storing the labels and the least features of flows.
    The entries of timed out flows are automatically removed.
    """

    @dataclasses.dataclass(frozen=False)
    class FlowData:
        """A data class to hold flow data."""
        last_seen_ms: int
        features: FeatureSchema
        label: Label

    def __init__(self, start_time_ms: int, flow_timeout_sec: int) -> None:
        self._start_time_ms: int = start_time_ms
        self._flow_timeout_sec: int = flow_timeout_sec

        self._timed_out_label_counts: Dict[Label, int] = dict()
        for label in Label:
            self._timed_out_label_counts[label] = 0

        self._entries: Dict[FlowId, FlowSingleLengthStorage.FlowData] = dict()
        self._entries_capacity: int = 65536  # Initial capacity of the entries, can grow later if necessary

    def get_stored(self, flow_id: FlowId, new_timestamp: int) -> Optional[Tuple[int, FeatureSchema, Label]]:
        """
        Gets the stored data of the specified flow.
        Updates the last seen timestamp of the flow with the new timestamp.
        """
        data = self._entries.get(flow_id, None)
        if data is None or data.last_seen_ms <= self._get_time_cutoff():
            return None
        last_timestamp, data.last_seen_ms = data.last_seen_ms, new_timestamp
        return last_timestamp, data.features, data.label

    def insert(self, flow_id: FlowId, features: FeatureSchema, last_seen_ms: int) -> None:
        """Adds a new flow to the storage."""
        self._delete_timed_out_entries_if_necessary()
        self._entries[flow_id] = FlowSingleLengthStorage.FlowData(
                last_seen_ms=last_seen_ms,
                features=features,
                label=Label.NOT_SET
        )

    def set_label(self, flow_id: FlowId, label: Label) -> None:
        """Assigns a label to the specified flow."""
        self._entries[flow_id].label = label

    def get_label_counts(self) -> Dict[Label, int]:
        """Returns how many flows were assigned each label."""
        result = dict(self._timed_out_label_counts)
        for data in self._entries.values():
            result[data.label] += 1
        return result

    def _get_time_cutoff(self) -> int:
        return time.time_ns() // 1_000_000 - self._start_time_ms - self._flow_timeout_sec * 1000

    def _delete_timed_out_entries_if_necessary(self) -> None:
        """If the entries have reached their capacity, delete timed out entries."""
        if len(self._entries) < self._entries_capacity:
            return

        cutoff_time_ms = self._get_time_cutoff()
        keep_entries = dict()
        for flow_id, data in self._entries.items():
            if data.last_seen_ms > cutoff_time_ms:
                keep_entries[flow_id] = data
            else:
                self._timed_out_label_counts[data.label] += 1

        timed_out_count = len(self._entries) - len(keep_entries)
        if timed_out_count > 0:
            _logger.debug(f"Removing {timed_out_count} timed out flow entries")
            self._entries = keep_entries
        else:
            _logger.debug("No timed out flow entries to remove, doubling capacity")
            self._entries_capacity *= 2


class FlowMultiLengthStorage:
    """
    Class responsible for storing flow data, features, and labels.
    Features at each flow length are stored.
    The entries of timed out flows are automatically removed.
    """

    def __init__(self, start_time_ms: int, max_classifiable_flow_length: int, flow_timeout_sec: int) -> None:
        self._start_time_ms: int = start_time_ms
        self._max_classifiable_flow_length: int = max_classifiable_flow_length
        self._flow_timeout_sec: int = flow_timeout_sec

        self._timed_out_label_counts: Dict[Label, int] = dict()
        for label in Label:
            self._timed_out_label_counts[label] = 0

        self._flow_to_index: Dict[FlowId, int] = dict()
        flow_array_size = 65536  # Initial capacity of the flow arrays
        self._flow_data: ListOfFlowDataSchema = np.zeros((flow_array_size, len(FlowDataCols)),
                                                         dtype=np.uint32)
        self._flow_features: ListOfFeaturesSchema = np.zeros(
                (flow_array_size, max_classifiable_flow_length, len(Feature)),
                dtype=np.uint32)
        self._flow_pred: ListOfFlowPredSchema = np.zeros((flow_array_size, len(FlowPredCols)),
                                                         dtype=np.uint32)
        self._flow_filled_count: int = 0

    def get_label(self, flow_id: FlowId) -> Label:
        """Gets the label assigned to the specified flow."""
        i = self._flow_to_index.get(flow_id)
        if i is None:
            return Label.NOT_SET
        else:
            return Label(int(self._flow_pred[i, FlowPredCols.PREDICTED_LABEL]))

    def set_label(self, flow_id: FlowId, label: Label) -> None:
        """Assigns a label to the specified flow."""
        i = self._flow_to_index.get(flow_id)
        if i is None:
            raise RuntimeError("Flow not found")
        self._flow_pred[i, FlowPredCols.PREDICTED_LABEL] = label.value

    def update_features(self, flow_id: FlowId, features: FeatureSchema) -> None:
        """
        Updates the stored features of the specified flow with the given features
        belonging to the next packet in the flow.
        """
        count_from_packet = features[Feature.COUNT]
        current_time_ms = time.time_ns() // 1_000_000 - self._start_time_ms
        cutoff_time_ms = current_time_ms - self._flow_timeout_sec * 1000

        # Get index previously associated with the flow
        i = self._flow_to_index.get(flow_id, None)

        # Request a new index if the flow has timed out
        if i is not None and self._flow_data[i, FlowDataCols.LAST_SEEN_MS] <= cutoff_time_ms:
            i = None

        # Ignore this data point if the maximum flow length has previously been reached
        if i is not None and count_from_packet > self._max_classifiable_flow_length:
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

            # TODO detect & handle if new_total_count > old_total_count + 1

            self._flow_data[i, FlowDataCols.LAST_SEEN_MS] = current_time_ms
            return

        # Insert new flow
        i = self._create_flow_index(flow_id)
        flow_id_begin, flow_id_end = FlowDataCols.flow_id_begin(), FlowDataCols.flow_id_end()
        self._flow_data[i, flow_id_begin:flow_id_end + 1] = flow_id.to_tuple()
        self._flow_data[i, FlowDataCols.SWITCH_ORDINAL] = 42
        self._flow_data[i, FlowDataCols.TOTAL_COUNT] = count_from_packet
        self._flow_data[i, FlowDataCols.FIRST_SEEN_MS] = current_time_ms
        self._flow_data[i, FlowDataCols.LAST_SEEN_MS] = current_time_ms
        self._flow_features[i, 0] = features
        self._flow_pred[i, FlowPredCols.PREDICTED_LABEL] = Label.NOT_SET
        self._flow_pred[i, FlowPredCols.PREDICTED_AT_COUNT] = 42

        # TODO detect & handle if new_total_count > old_total_count + 1

    def get_flow_features(self, flow_id: FlowId, flow_length: int) -> FeatureSchema:
        """
        Retrieves the features of the specified flow at the specified flow length.
        Check `get_total_count` to determine the last available flow length.
        """
        i = self._flow_to_index.get(flow_id)
        if i is None:
            raise RuntimeError("Flow not found")
        return self._flow_features[i, flow_length - 1]

    def get_total_count(self, flow_id: FlowId) -> int:
        """The number of packets received for the specified flow."""
        i = self._flow_to_index.get(flow_id)
        if i is None:
            return 0
        else:
            return int(self._flow_data[i, FlowDataCols.TOTAL_COUNT])

    def get_label_counts(self) -> Dict[Label, int]:
        """Returns how many flows were assigned each label."""
        result = dict(self._timed_out_label_counts)
        for flow_id in self._flow_to_index.keys():
            result[self.get_label(flow_id)] += 1
        return result

    def _create_flow_index(self, flow_id: FlowId) -> int:
        """Returns the flow index for the specified flow ID, creating a new entry if necessary."""

        # Remove timed out flows if no free index is available
        if len(self._flow_data) == self._flow_filled_count:
            # Locate the flows that should be kept
            current_time_ms = time.time_ns() // 1_000_000 - self._start_time_ms
            cutoff_time_ms = current_time_ms - self._flow_timeout_sec * 1000
            keep_mask = self._flow_data[:, FlowDataCols.LAST_SEEN_MS] > cutoff_time_ms
            keep_count = np.count_nonzero(keep_mask)

            if keep_count < len(self._flow_data):  # At least 1 flow can be removed
                # Update timed out label counts
                for i in self._flow_to_index.keys():
                    if not keep_mask[i]:
                        label = Label(int(self._flow_pred[i, FlowPredCols.PREDICTED_LABEL]))
                        self._timed_out_label_counts[label] += 1

                # Move the kept flows to the front of the array
                self._flow_data[0:keep_count] = self._flow_data[keep_mask]
                self._flow_features[0:keep_count] = self._flow_features[keep_mask]
                self._flow_pred[0:keep_count] = self._flow_pred[keep_mask]

                # Update the flow-to-index mapping
                self._flow_to_index.clear()
                for i, data_row in enumerate(self._flow_data[0:keep_count]):
                    # noinspection PyTypeChecker
                    self._flow_to_index[FlowId.from_ndarray(data_row, FlowDataCols.flow_id_begin())] = i
                self._flow_filled_count = keep_count
                _logger.debug(f"Removed {len(self._flow_data) - keep_count} timed out flows")
            else:
                # Resize the arrays if no flows could be removed
                new_size = len(self._flow_data) * 2
                _logger.debug(f"Resizing flow arrays to size {new_size}")
                self._flow_data.resize((new_size, *self._flow_data.shape[1:]))
                self._flow_features.resize((new_size, *self._flow_features.shape[1:]))
                self._flow_pred.resize((new_size, *self._flow_pred.shape[1:]))

        # A free index is available now, no matter what
        i = self._flow_filled_count
        self._flow_to_index[flow_id] = i
        self._flow_filled_count += 1
        return i
