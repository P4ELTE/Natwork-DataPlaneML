import abc
import logging
from typing import Dict

import numpy as np

from lib_common.dataset.label_csv import LabelCsvLoader
from lib_common.flow import ListOfLabelSchema, ListOfFeaturesSchema, ListOfFlowDataSchema, FlowId, Label, \
    FlowDataCols
from oracle.interface import ControllerInterfaceHandler

_logger = logging.getLogger(__name__)


class OracleLogic(ControllerInterfaceHandler):
    """The main logic of the oracle (reliable flow classifier) component."""

    @abc.abstractmethod
    def initialize(self) -> None:
        """
        Initializes the class instance. This method should be called before any other method.
        It is responsible for setting up connections, starting threads, loading data, etc.
        """
        pass


class StatisticsCollectorOracleLogic(OracleLogic):
    """A decorator that collects statistics about the flow classification results."""

    def __init__(self, inner_logic: OracleLogic) -> None:
        self._inner_logic: OracleLogic = inner_logic
        # dtype=int is used, because np.bincount will also return int (np.uint64) values
        self._counts: np.ndarray = np.zeros((len(Label),), dtype=int)

    def initialize(self) -> None:
        self._inner_logic.initialize()

    def handle_flow_classification_request(self, flow_data: ListOfFlowDataSchema,
                                           flow_features: ListOfFeaturesSchema) -> ListOfLabelSchema:
        labels = self._inner_logic.handle_flow_classification_request(flow_data, flow_features)
        self._counts += np.bincount(labels, minlength=len(Label))
        _logger.info(f"Classification statistics until now (same flow can be classified multiple times):"
                     f" {Label.compute_count_statistics(labels, counts=self._counts)}")
        return labels


class LabelCsvMockOracleLogic(OracleLogic):
    """
    A logic implementation that reads the labels from a CSV file: the CSV file maps flow IDs to their labels.
    """

    def __init__(self, csv_loader: LabelCsvLoader, default_label: Label = Label.NOT_SET) -> None:
        self._csv_loader = csv_loader
        self._default_label = default_label
        self._flow_to_label: Dict[FlowId, int] = dict()

    def initialize(self) -> None:
        self._flow_to_label = self._csv_loader.load_flow_to_label()

    def handle_flow_classification_request(self, flow_data: ListOfFlowDataSchema,
                                           flow_features: ListOfFeaturesSchema) -> ListOfLabelSchema:
        count = flow_data.shape[0]
        result = np.ndarray((count,), dtype=np.uint32)

        for i in range(count):
            flow_id = FlowId.from_ndarray(flow_data[i], FlowDataCols.flow_id_begin())
            label = self._flow_to_label.get(flow_id, None)
            if label is None:
                _logger.warning(f"Flow not found in the CSV file: {flow_id}")
                label = self._default_label.value
            result[i] = label

        return result
