import abc
import dataclasses
import logging
from typing import Dict, List, Set, Tuple

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

from lib_common.control_plane.data import ControlledSwitch
from lib_common.data import SwitchConstants
from lib_common.flow import Feature, Label
from lib_common.model.data import Model, ModelSlice, ModelTrainingConfig
from lib_common.model.model_ops import remap_model_rf_ids, slice_model
from p4_api_bridge import TofinoShellApiConfig

_logger = logging.getLogger(__name__)


class ModelEncoder(abc.ABC):
    """Class responsible for encoding random forests into the data plane."""

    def __init__(self, switch_constants: SwitchConstants, switches: List[ControlledSwitch]) -> None:
        self._sw_const = switch_constants
        self._abort = False
        self._switches: List[ControlledSwitch] = switches
        self._used_rf_ids: Set[int] = set()  # RF IDs that are currently in use by this controller's switches
        self._used_flow_lengths: Set[int] = set()  # Flow lengths that are currently mapped to an RF ID

    def load_model(self, model: Model, certainty_threshold: float) -> None:
        """
        Loads the specified in-network flow classification model into the provided switches.
        To achieve a hit-less model switchover, the uploading is done in the following steps:
        - The model is remapped to RF IDs that are not currently in use by the switches.
        - Then, the new model is uploaded to all switches.
        - Finally, the switches are instructed to start using the new model.
        - (Extra: optionally execute any post-loading cleanup operations.)
        This way all switches will start using the new model at the same time.

        Unfortunately, to achieve this, we need to have enough memory for twice as many RFs as we actually need.
        This is because multiple flow lengths might map to the same RF, therefore we can't replace RFs one-by-one.
        """
        _logger.info("Loading model into switches...")

        # A model might already be encoded into the network which could be using some of the same IDs the new model uses
        # To achieve a hit-less switchover, we need to be able to use the old model while the new model is being loaded
        free_rf_ids = (i for i in range(1, self._sw_const.max_rf_count * 2 + 1) if i not in self._used_rf_ids)
        model = remap_model_rf_ids(model, free_rf_ids)

        # TODO better logic to decide which DTs to encode to which switch (replace this placeholder implementation)
        switch_to_dt_whitelist: Dict[str, Set[int]] = {s.name: set() for s in self._switches}
        # Whitelist as many DTs on the first switch as possible, then move on to the next switch
        for dt_id in range(self._sw_const.dt_per_rf_count):
            switch_to_dt_whitelist[self._switches[dt_id // self._sw_const.dt_per_switch_count].name].add(dt_id)

        # Load the individual model slices into the switches
        model_slices = slice_model(model, list(switch_to_dt_whitelist.values()))
        for switch, model_slice in zip(self._switches, model_slices):
            with switch.api.try_create_batch():
                self._load_model_slice(switch, model_slice, certainty_threshold)
            if self._check_abort():
                return

        # Start using the new model
        for switch, model_slice in zip(self._switches, model_slices):
            _logger.debug(f"Updating flow length to RF ID mappings in {switch}...")
            with switch.api.try_create_batch():
                for rf_id in model_slice.id_to_rf.keys():
                    for length in model_slice.id_to_flow_lengths[rf_id]:
                        switch.api.table_modify_or_add(length in self._used_flow_lengths,
                                                       "MyIngress.rf_id_table", [length],
                                                       "MyIngress.set_rf_id", [rf_id])
                # Some flow lengths previously had an RF mapped to them, but no longer do. Delete these mappings.
                for length in self._used_flow_lengths - set(model_slice.flow_length_to_id.keys()):
                    switch.api.table_delete("MyIngress.rf_id_table", [length])
            if self._check_abort():
                return

        # Cleanup, if necessary
        for switch, model_slice in zip(self._switches, model_slices):
            with switch.api.try_create_batch():
                self._clean_after_load(switch, model_slice)
            if self._check_abort():
                return

        # Update controller state
        self._used_rf_ids = set(model.id_to_rf.keys())
        self._used_flow_lengths = set(model.flow_length_to_id.keys())
        _logger.info("Finished loading model")

    @abc.abstractmethod
    def _load_model_slice(self, switch: ControlledSwitch, model_slice: ModelSlice, certainty_threshold: float) -> None:
        """
        Loads the specified model slice into the provided switch.
        This method only loads the model slice into the switch, but doesn't "activate" it.
        Switch operations are automatically batched.
        """
        raise NotImplementedError

    def _clean_after_load(self, switch: ControlledSwitch, loaded_model_slice: ModelSlice) -> None:
        """
        Optional cleanup operation that can be performed after a model slice has been loaded into a switch.
        Switch operations are automatically batched.
        """
        pass

    def abort(self) -> None:
        """Aborts the model loading process and stops future processes from starting."""
        self._abort = True

    def _check_abort(self) -> bool:
        """Checks if the model loading process should be aborted. If yes, then logs the event and returns True."""
        if self._abort:
            _logger.info("Abort flag is set; aborting model loading process...")
            return True
        return False


class TablePerDepthModelEncoder(ModelEncoder):
    """Encoding method that uses a separate match-action table for each depth of each decision tree."""

    @dataclasses.dataclass
    class _SwitchData:
        """Container for switch-specific data, e.g. the occupied match-action table entry keys."""
        occupied_dt_entries: Set[Tuple[int, int, int, int, int]] = dataclasses.field(default_factory=set)
        """
        Set of (rf_id, dt_id, depth, parent_node+1, threshold_passed) tuples that are present in the switch's tables.
        These may or may not actually be used by the current model: they might be leftovers from a previous model.
        They aren't deleted, because deleting them would be a waste of time without freeing up resources.
        """

    def __init__(self, switch_constants: SwitchConstants, switches: List[ControlledSwitch]) -> None:
        super().__init__(switch_constants, switches)
        self._switch_data: Dict[str, TablePerDepthModelEncoder._SwitchData] = \
            {switch.name: TablePerDepthModelEncoder._SwitchData() for switch in switches}

    def _load_model_slice(self, switch: ControlledSwitch, model_slice: ModelSlice, certainty_threshold: float) -> None:
        _logger.debug(f"Encoding random forest into {switch}...")
        for rf_id, rf_slice in model_slice.id_to_rf.items():
            for dt_num, (original_dt_i, dt) in enumerate(rf_slice.dts_and_indexes):
                self._fill_decision_tree_table(switch, rf_id, dt_num, rf_slice.original.classifier, dt)
                switch.api.register_set('MyIngress.dt_num_to_dt_id_bitflag_register', dt_num, 1 << original_dt_i)
                if self._check_abort():
                    return

        certainty_sum_threshold_per_executed_dt = round(self._sw_const.certainty_type_max_value * certainty_threshold)
        switch.api.register_set('MyIngress.rf_certainty_sum_threshold_per_executed_dt_register',
                                0, certainty_sum_threshold_per_executed_dt)

    def _fill_decision_tree_table(self, switch: ControlledSwitch,
                                  rf_id: int, dt_num: int, rf: RandomForestClassifier,
                                  dt: DecisionTreeClassifier) -> None:
        """Encodes a single decision tree into the switch's match-action tables."""
        switch_data = self._switch_data[switch.name]

        # We use two distinct node identifiers:
        # - Scikit uses its internal node IDs. Each ID only appears once in the tree and they are consecutive.
        #   They do not reset at each depth.
        # - To index the match-action tables, we use a different ID scheme, that are unique within a given depth.
        #   This allows us to overwrite previous entries in the tree without having to delete them first,
        #   while still ensuring that the count of entries at a given depth (within a RF) is at most 2^depth.

        # Threshold passed is a boolean that indicates whether the threshold was passed (1) or not (0).
        stack = [(0, 0, 0, 0)]  # parent_mat_id, node, depth, threshold_passed
        while len(stack) > 0:
            parent_mat_id, node_scikit_id, depth, threshold_passed = stack.pop()
            node_mat_id = parent_mat_id * 2 + threshold_passed
            table_name = f'MyIngress.dt_{dt_num}_depth_{depth}_table'
            table_keys = [rf_id, parent_mat_id, threshold_passed]
            tuple_key = (rf_id, dt_num, depth, parent_mat_id, threshold_passed)  # Vars of table_name and table_keys

            if dt.tree_.children_left[node_scikit_id] == dt.tree_.children_right[node_scikit_id]:  # Leaf node
                action_name = 'MyIngress.inference_process_node_final'
                sample_counts = dt.tree_.value[node_scikit_id]
                label, certainty = rf.classes_[np.argmax(sample_counts)], np.max(sample_counts) / np.sum(sample_counts)
                action_params = [label, round(certainty * self._sw_const.certainty_type_max_value)]
            else:  # Split node
                action_name = 'MyIngress.inference_process_node'
                # Floor the threshold: x <= #.5 is equivalent to x <= floor(#.5) if x is an integer
                feature, threshold = dt.tree_.feature[node_scikit_id], int(np.floor(dt.tree_.threshold[node_scikit_id]))
                action_params = [node_mat_id, feature, threshold]
                stack.append((node_mat_id, dt.tree_.children_left[node_scikit_id], depth + 1, 0))
                stack.append((node_mat_id, dt.tree_.children_right[node_scikit_id], depth + 1, 1))

            switch.api.table_modify_or_add(tuple_key in switch_data.occupied_dt_entries,
                                           table_name, table_keys, action_name, action_params)
            switch_data.occupied_dt_entries.add(tuple_key)


class TablePerTreeModelEncoder(ModelEncoder):
    """Encoding method that uses a single match-action table for each decision tree."""

    @dataclasses.dataclass
    class _SwitchData:
        """Container for switch-specific data, e.g. the occupied match-action table entry keys."""
        old_dt_to_table_keys: Dict[int, List] = dataclasses.field(default_factory=dict)
        new_dt_to_table_keys: Dict[int, List] = dataclasses.field(default_factory=dict)
        old_certainty_threshold: float = dataclasses.field(default=-1.0)

    def __init__(self, switch_constants: SwitchConstants, switches: List[ControlledSwitch],
                 training_config: ModelTrainingConfig) -> None:
        super().__init__(switch_constants, switches)
        self._training_config: ModelTrainingConfig = training_config
        self._switch_data: Dict[str, TablePerTreeModelEncoder._SwitchData] = \
            {switch.name: TablePerTreeModelEncoder._SwitchData() for switch in switches}

    def _load_model_slice(self, switch: ControlledSwitch, model_slice: ModelSlice, certainty_threshold: float) -> None:
        switch_data = self._switch_data[switch.name]

        # Noop if the model is empty
        if len(model_slice.id_to_rf) == 0:
            return

        # Calculate which DT ID is placed in which DT slot in this switch
        # TODO we assume that the DT ID - DT NUM mapping is the same for each RF
        dt_id_to_dt_num = dict()
        for rf_id, rf_slice in model_slice.id_to_rf.items():
            for within_switch_dt_num, (universal_dt_id, dt) in enumerate(rf_slice.dts_and_indexes):
                dt_id_to_dt_num[universal_dt_id] = within_switch_dt_num
        assert len(dt_id_to_dt_num) == self._sw_const.dt_per_switch_count

        # TODO we assume that the same DT ID is placed into the same DT NUM during each model update
        if switch_data.old_certainty_threshold < 0:  # Execute code if no initialization has been done yet
            # It is easier to understand this code by looking at the control plane code first:
            #   that way it will be clear what this code is trying to achieve (the goal is simple, the code is not)
            for dt_id_bitflag in range(2 ** self._sw_const.dt_per_rf_count):
                updated_bitflag = dt_id_bitflag
                updated_executed_count = sum([int(d) for d in bin(updated_bitflag)[2:]])  # Count the number of 1s
                execute_dt_num = [0] * self._sw_const.dt_per_switch_count

                for dt_id, dt_num in dt_id_to_dt_num.items():
                    if (1 << dt_id) & updated_bitflag == 0:
                        updated_bitflag |= 1 << dt_id
                        updated_executed_count += 1
                        execute_dt_num[dt_num] = 1

                params = [updated_bitflag, updated_executed_count] + execute_dt_num
                switch.api.table_add('MyIngress.dt_id_bitflag_table', [dt_id_bitflag],
                                     'MyIngress.dt_id_bitflag_table_action', params)
                if self._check_abort():
                    return

        for rf_id, rf_slice in model_slice.id_to_rf.items():
            for within_switch_dt_num, (universal_dt_id, dt) in enumerate(rf_slice.dts_and_indexes):
                self._load_tree(switch, rf_id, within_switch_dt_num, dt)
                if self._check_abort():
                    return

        if switch_data.old_certainty_threshold != certainty_threshold:
            switch_data.old_certainty_threshold = certainty_threshold
            switch.api.table_clear('MyIngress.certainties_to_verdict_table')

            # TODO We expect all DTs to be computed. Possible fix: add the executed DT count as an extra key
            # TODO we expect there to be at most 1 label that surpasses the threshold (what if we add a 3rd label?)
            assert certainty_threshold > 0.5, "Certainty threshold must be at least 0.5, guaranteeing at most 1 winning label"
            max_certainty_sum = self._sw_const.certainty_type_max_value * self._sw_const.dt_per_rf_count
            certainty_sum_threshold = round(max_certainty_sum * certainty_threshold)
            for label in Label.excluding_not_set():
                match_keys = [f'0..{certainty_sum_threshold - 1}'] * len(Label.excluding_not_set())
                match_keys[label.value - 1] = f'{certainty_sum_threshold}..{max_certainty_sum}'
                switch.api.table_add('MyIngress.certainties_to_verdict_table', match_keys,
                                     'MyIngress.certainties_to_verdict_table_action', [0, label.value])  # match_priority=0

    def _load_tree(self, switch: ControlledSwitch, rf_id: int, dt_num: int, dt: DecisionTreeClassifier) -> None:
        """Encodes a single decision tree into a match-action table."""
        switch_data = self._switch_data[switch.name]
        if dt_num not in switch_data.new_dt_to_table_keys:
            switch_data.new_dt_to_table_keys[dt_num] = []
        for feature_ranges, label, certainty in self._tree_to_feature_ranges(dt):
            certainty: int = round(certainty * self._sw_const.certainty_type_max_value)
            match_keys = [rf_id] + [f'{a}..{b}' for a, b in feature_ranges]
            switch.api.table_add(f'MyIngress.dt_{dt_num}_table', match_keys,
                                 f'MyIngress.dt_label_{label + 1}_action', [0, certainty])  # match_priority=0
            switch_data.new_dt_to_table_keys[dt_num].append(match_keys)

    def _clean_after_load(self, switch: ControlledSwitch, loaded_model_slice: ModelSlice) -> None:
        switch_data = self._switch_data[switch.name]
        # Get rid of no longer used range match entries
        for dt_num, match_keys_list in switch_data.old_dt_to_table_keys.items():
            for match_keys in match_keys_list:
                switch.api.table_delete(f'MyIngress.dt_{dt_num}_table', match_keys)
        switch_data.old_dt_to_table_keys = switch_data.new_dt_to_table_keys
        switch_data.new_dt_to_table_keys = dict()

    def _tree_to_feature_ranges(self, dt: DecisionTreeClassifier) -> List[Tuple[List[Tuple[int, int]], int, float]]:
        """
        Converts a decision tree to a 'feature-range to label & certainty' mapping.
        The features that should be used must be explicitly specified, because the tree might not use all features,
        which would lead to the unused features not being present in the resulting mapping.
        """
        result: List[Tuple[List[Tuple[int, int]], int, float]] = []

        def traverse(node_id: int, feature_bounds: List[Tuple[int, int]]) -> None:
            if dt.tree_.children_left[node_id] == dt.tree_.children_right[node_id]:  # Leaf node
                sample_counts = dt.tree_.value[node_id]
                label, certainty = dt.classes_[np.argmax(sample_counts)], np.max(sample_counts) / np.sum(sample_counts)
                result.append((feature_bounds.copy(), int(label), float(certainty)))
            else:  # Split node
                # Flooring is the correct operation here, see other encoding method for details
                feature, threshold = dt.tree_.feature[node_id], int(np.floor(dt.tree_.threshold[node_id]))

                # Remap the feature value (feature index): only consider enabled features
                feature = self._training_config.enabled_features.index(Feature(feature))

                left_bounds = feature_bounds.copy()
                left_bounds[feature] = (left_bounds[feature][0], threshold)
                traverse(dt.tree_.children_left[node_id], left_bounds)

                right_bounds = feature_bounds  # No need to copy, it's safe to mutate now
                right_bounds[feature] = (threshold + 1, right_bounds[feature][1])  # +1, because bounds are inclusive
                traverse(dt.tree_.children_right[node_id], right_bounds)

        traverse(0, [(0, f.max_value) for f in self._training_config.enabled_features])
        return result


def create_model_encoder(switch_constants: SwitchConstants, switches: List[ControlledSwitch],
                         training_config: ModelTrainingConfig) -> ModelEncoder:
    """Creates the appropriate model encoder based on the switch type."""
    if isinstance(switches[0].config.switch_type, TofinoShellApiConfig):
        return TablePerTreeModelEncoder(switch_constants, switches, training_config)
    else:
        return TablePerDepthModelEncoder(switch_constants, switches)
