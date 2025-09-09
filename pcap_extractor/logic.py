import logging
from typing import Dict, Optional, Tuple

import dpkt
import numpy as np

from lib_common import feature_extraction
from lib_common.flow import Feature, FlowDataCols, FlowId, Label, ListOfFeaturesSchema, ListOfFlowDataSchema, \
    ListOfLabelSchema

_logger = logging.getLogger(__name__)


def extract_features(max_flow_length: int,
                     pcap_reader: dpkt.pcap.Reader) -> Tuple[ListOfFlowDataSchema, ListOfFeaturesSchema]:
    """
    Extracts the features and the flow data from the flows found inside the provided PCAP.
    """
    initial_capacity = 4096
    flow_data = np.zeros((initial_capacity, len(FlowDataCols)), dtype=np.uint32)
    flow_features = np.zeros((initial_capacity, max_flow_length, len(Feature)), dtype=np.uint32)

    flow_to_index: Dict[FlowId, int] = dict()
    first_timestamp: Optional[int] = None

    count = 0
    # Iterate through the packets in the PCAP file
    for timestamp, packet in pcap_reader:
        count += 1
        if count % 100000 == 0:
            _logger.debug(f"Progress: at {count} packets, {len(flow_to_index)} flows found so far...")

        eth = dpkt.ethernet.Ethernet(packet)
        if not isinstance(eth.data, dpkt.ip.IP):
            continue

        ip: dpkt.ip.IP = eth.data
        timestamp = int(timestamp * 1000)  # Convert seconds to milliseconds
        if first_timestamp is None:
            first_timestamp = timestamp
        timestamp -= first_timestamp

        flow_id = FlowId.from_dpkt_packet(ip)
        features = feature_extraction.parse_packet(ip)
        i = flow_to_index.get(flow_id)

        # Resize the arrays if we run out of space
        if i is None and len(flow_data) == len(flow_to_index):
            new_capacity = len(flow_data) * 2
            _logger.debug(f"Increasing capacity of flow arrays to {new_capacity}")
            flow_data.resize((new_capacity, *flow_data.shape[1:]))
            flow_features.resize((new_capacity, *flow_features.shape[1:]))

        # New flow, add it to the arrays
        if i is None:
            i = len(flow_to_index)
            flow_to_index[flow_id] = i
            flow_data[i, FlowDataCols.flow_id_begin():FlowDataCols.flow_id_end() + 1] = flow_id.to_tuple()
            flow_data[i, FlowDataCols.TOTAL_COUNT] = 1
            flow_data[i, FlowDataCols.FIRST_SEEN_MS] = timestamp
            flow_data[i, FlowDataCols.LAST_SEEN_MS] = timestamp
            flow_features[i, 0] = features
            continue

        # Existing flow, merge the features
        old_count, old_timestamp = flow_data[i, FlowDataCols.TOTAL_COUNT], flow_data[i, FlowDataCols.LAST_SEEN_MS]
        if old_count == max_flow_length:
            continue  # Maximum flow length reached, ignore further packets for this flow
        else:
            flow_data[i, FlowDataCols.TOTAL_COUNT] = old_count + 1
            flow_data[i, FlowDataCols.LAST_SEEN_MS] = timestamp
            flow_features[i, old_count] = flow_features[i, old_count - 1]  # First flow length (count=1) is at index 0
            feature_extraction.merge_features(flow_features[i, old_count], int(old_timestamp), features, timestamp)
            assert flow_features[i, old_count, Feature.COUNT] == old_count + 1
            assert flow_features[i, old_count, Feature.LENGTH_SUM] > flow_features[i, old_count - 1, Feature.LENGTH_SUM]

    _logger.info(f"Finished reading PCAP, packet count: {count}")
    size = len(flow_to_index)
    return flow_data[:size], flow_features[:size]


def pair_labels(flow_data: ListOfFlowDataSchema, labels: Dict[FlowId, int]) -> ListOfLabelSchema:
    """
    Creates a numpy array of labels with matching indexes to the flow data, filling the array with the provided labels.
    """
    flow_true_labels = np.zeros(len(flow_data), dtype=np.uint32)
    for i in range(len(flow_data)):
        flow_id = FlowId.from_ndarray(flow_data[i], FlowDataCols.flow_id_begin())
        flow_true_labels[i] = labels.get(flow_id, Label.NOT_SET.value)
    return flow_true_labels
