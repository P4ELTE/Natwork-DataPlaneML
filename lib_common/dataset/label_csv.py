import abc
import csv
import logging
import pickle
from pathlib import Path

from typing import Dict, List, Optional

import numpy as np

from lib_common.flow import FlowId, Label

_logger = logging.getLogger(__name__)


class LabelCsvLoader(abc.ABC):
    """Class responsible for loading flow IDs and labels from a CSV file."""

    @abc.abstractmethod
    def load_flow_to_label(self) -> Dict[FlowId, int]:
        """
        Loads the flow IDs and labels from the CSV file and returns them as a dictionary.
        Loading might take a while, so this method should be called only once.
        """
        pass


class CachingLabelCsvLoader(LabelCsvLoader):
    """A decorator for a label loader that caches the loaded labels to a file."""

    def __init__(self, inner_loader: LabelCsvLoader, cache_path: Path) -> None:
        self._inner_loader: LabelCsvLoader = inner_loader
        self._cache_path: Path = cache_path

    def load_flow_to_label(self) -> Dict[FlowId, int]:
        if self._cache_path.exists():
            _logger.info(f"Returning cached labels found at: {self._cache_path}")
            with self._cache_path.open('rb') as file:
                return pickle.load(file)
        else:
            data = self._inner_loader.load_flow_to_label()
            _logger.info(f"Saving label cache to: {self._cache_path}")
            self._cache_path.parent.mkdir(parents=True, exist_ok=True)
            with self._cache_path.open('wb') as file:
                # noinspection PyTypeChecker
                pickle.dump(data, file)
            return data


class BasicLabelCsvLoader(LabelCsvLoader):
    """A simple implementation of a label loader that can be used as a base class for more concrete loaders."""

    def __init__(self, csv_path: Path, encoding: str) -> None:
        self._csv_path: Path = csv_path
        self._encoding: str = encoding

    def load_flow_to_label(self) -> Dict[FlowId, int]:
        _logger.info(f"Loading labels from {self._csv_path}...")

        count_empty, count_duplicate, count_conflicting = 0, 0, 0
        flow_to_label: Dict[FlowId, int] = dict()  # Maps flow IDs to their respective labels
        unparsed_label_to_count: Dict[str, int] = dict()

        with open(self._csv_path, newline='', encoding=self._encoding) as csvfile:
            for row in csv.DictReader(csvfile):
                row: Dict[str, str] = row

                if self._is_row_empty(row):
                    count_empty += 1
                    self._handle_empty_row()
                    continue

                flow = self._row_to_flow_id(row)
                unparsed_label = self._row_to_unparsed_label(row)
                label = self._parse_label(unparsed_label)
                old_label = flow_to_label.get(flow, None)

                if old_label is None:
                    flow_to_label[flow] = label
                    unparsed_label_to_count[unparsed_label] = 1 + unparsed_label_to_count.get(unparsed_label, 0)
                elif old_label == label:
                    count_duplicate += 1
                    self._handle_duplicate_flow(flow, label)
                elif old_label != label:
                    count_conflicting += 1
                    self._handle_conflicting_flow(flow, old_label, label)

        count_total = len(flow_to_label) + count_empty + count_duplicate + count_conflicting

        def count_to_percentage(count: int, total: int) -> float:
            return count / total * 100 if total > 0 else 0

        _logger.info(f"Loaded {len(flow_to_label)} labels"
                     f" ({count_to_percentage(len(flow_to_label), count_total):.2f}% of all rows)")
        if count_empty > 0:
            _logger.warning(f"  {count_empty} rows were empty"
                            f" ({count_to_percentage(count_empty, count_total):.2f}% of all rows)")
        if count_duplicate > 0:
            _logger.warning(f"  {count_duplicate} rows had previously seen flow IDs with the same label"
                            f" ({count_to_percentage(count_duplicate, count_total):.2f}% of all rows)")
        if count_conflicting > 0:
            _logger.warning(f"  {count_conflicting} rows had previously seen flow IDs with different labels"
                            f" ({count_to_percentage(count_conflicting, count_total):.2f}% of all rows)")

        labels_array = np.asarray(list(flow_to_label.values()), dtype=np.uint32)
        _logger.info(f"  Label statistics: {Label.compute_count_statistics(labels_array)}")

        # Display the unparsed label statistics in decreasing order of number of occurrences
        count_total = sum(unparsed_label_to_count.values())
        pairs = sorted(((unparsed, count) for unparsed, count in unparsed_label_to_count.items()),
                       key=lambda pair: pair[1], reverse=True)
        pairs = (f"{unparsed}: {count} ({round(count / count_total * 100)}%)" for unparsed, count in pairs)
        _logger.info(f'  Unparsed label statistics: {"; ".join(pairs)}')

        return flow_to_label

    @abc.abstractmethod
    def _is_row_empty(self, row: Dict[str, str]) -> bool:
        """Method that determines whether a row is empty and should be skipped."""
        pass

    @abc.abstractmethod
    def _row_to_flow_id(self, row: Dict[str, str]) -> FlowId:
        """Method that extracts the flow ID from a row."""
        pass

    @abc.abstractmethod
    def _row_to_unparsed_label(self, row: Dict[str, str]) -> str:
        """
        Method that extracts the label from a row. The label is not yet parsed.
        This allows the parsing operation to combine multiple actual labels into a single logical label,
        while still allowing the CSV loader to print the original label statistics.
        """
        pass

    @abc.abstractmethod
    def _parse_label(self, unparsed_label: str) -> int:
        """Method that parses the label into a numerical value (the numerical value of a Label constant)."""
        pass

    def _handle_empty_row(self) -> None:
        """Method that is called when an empty row is encountered."""
        pass

    def _handle_duplicate_flow(self, flow: FlowId, label: int) -> None:
        """Method that is called when a flow ID is encountered that has already been seen with the same label."""
        pass

    def _handle_conflicting_flow(self, flow: FlowId, label_old: int, label_new: int) -> None:
        """Method that is called when a flow ID is encountered that has already been seen with a different label."""
        pass


class CicidsCsvLoader(BasicLabelCsvLoader):
    """
    A label loader for the CICIDS 2017 dataset.
    By default, all non-benign flows are considered attacks, but it is possible to specify a single attack type instead.
    """

    def __init__(self, csv_path: Path, attack_type_whitelist: List[str] = None) -> None:
        super().__init__(csv_path, 'cp1252')
        self._attack_type_whitelist: Optional[List[str]] = None
        if attack_type_whitelist:
            self._attack_type_whitelist = [x.lower() for x in attack_type_whitelist]
            _logger.info(f"Only considering these attack types: {self._attack_type_whitelist}")
        else:
            _logger.info('The attack type whitelist is not set, considering all attack types')


    def _is_row_empty(self, row: Dict[str, str]) -> bool:
        return row[' Label'] == ''

    def _row_to_flow_id(self, row: Dict[str, str]) -> FlowId:
        return FlowId.from_strings(row[' Source IP'], row[' Destination IP'], row[' Protocol'],
                                   row[' Source Port'], row[' Destination Port'])

    def _row_to_unparsed_label(self, row: Dict[str, str]) -> str:
        return row[' Label']

    def _parse_label(self, unparsed_label: str) -> int:
        if self._attack_type_whitelist is not None:
            return Label.ATTACK.value if (unparsed_label.lower() in self._attack_type_whitelist) else Label.BENIGN.value
        else:
            return Label.BENIGN.value if unparsed_label == "BENIGN" else Label.ATTACK.value


class ImprovedCicidsCsvLoader(CicidsCsvLoader):
    """
    A label loader for the Improved CICIDS 2017 dataset.
    By default, all non-benign flows are considered attacks, but it is possible to specify a single attack type instead.
    """

    def __init__(self, csv_path: Path, attack_type_whitelist: List[str] = None) -> None:
        super().__init__(csv_path, attack_type_whitelist)

    def _is_row_empty(self, row: Dict[str, str]) -> bool:
        return row['Label'] == ''

    def _row_to_flow_id(self, row: Dict[str, str]) -> FlowId:
        return FlowId.from_strings(row['Src IP'], row['Dst IP'], row['Protocol'],
                                   row['Src Port'], row['Dst Port'])

    def _row_to_unparsed_label(self, row: Dict[str, str]) -> str:
        return row['Label']

    def _parse_label(self, unparsed_label: str) -> int:
        result = super()._parse_label(unparsed_label)
        # Fix incorrectly labeled flows that were fixed in the improved dataset
        return Label.BENIGN.value if result == Label.ATTACK.value and "Attempted" in unparsed_label else result
