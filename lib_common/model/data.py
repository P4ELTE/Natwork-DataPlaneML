import dataclasses
from typing import Dict, List, Tuple, Union

from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier

from lib_common.data import SwitchConstants
from lib_common.flow import Feature


@dataclasses.dataclass(frozen=True)
class ModelTrainingConfig:
    """Configuration of how models should be trained."""
    classification_certainty_threshold: float  # Minimum certainty at which a label is accepted
    rf_score_threshold_old_over_new: float  # Threshold to reuse an old RF before a new one is even considered
    rf_score_threshold_new: float  # Threshold to accept a newly trained RF
    rf_score_threshold_old_over_none: float  # Threshold to reuse old RF instead of having no RF for flow length
    rf_score_penalize_below_classified_ratio: float  # Penalize RFs that classify less than this ratio of flows
    rf_max_n_estimators: int  # Maximum value of a respective hyperparameter
    rf_max_max_depth: int  # Maximum value of a respective hyperparameter
    max_rf_count: int  # Maximum number of random forests
    max_classifiable_flow_length: int  # Maximum flow length that can be classified
    enabled_features: List[Feature]  # See disabled_features for the opposite
    use_time_based_features: bool = False  # Whether to use time-based features, e.g. inter-arrival time, flow duration
    rf_split_min_samples: Union[int, float] = 10  # Inner nodes have at least this many (or fraction of) samples
    rf_node_min_samples: Union[int, float] = 2  # All nodes have at least this many (or fraction of) samples
    rf_benign_label_weight: float = 5.0  # Weight of benign flows compared to other labels
    rf_age_weight_exp_base: float = -750.0  # Newer flows get exponentially more weight: oldest: *b^0; newest: *b^1
    rf_age_weight_lerp_max: float = -1  # Newer flows get linearly more weight: oldest: *1; newest: *max
    rf_train_test_split: float = -1  # Ratio of training when a new RF is trained; -1 to use all for train and test
    random_seed: int = 42
    rf_hyperopt_enabled: bool = False  # Whether to use hyperparameter optimization for RF training
    rf_hyperopt_iterations: int = 10  # Number of iterations for hyperparameter optimization
    rf_hyperopt_cv_folds: int = 3  # Number of cross-validation folds for hyperparameter optimization
    rf_hyperopt_penalty_n_estimators: float = 0.01  # Tuning score is penalized by: this*(param_value / max_param_value)
    rf_hyperopt_penalty_max_depth: float = 0.01  # Tuning score is penalized by: this*(param_value / max_param_value)

    def __post_init__(self) -> None:
        if self.enabled_features != [f for f in Feature if f in self.enabled_features]:
            raise ValueError(f"Enabled features must be an ordered sublist of Features")

    @property
    def disabled_features(self) -> List['Feature']:
        """
        The opposite of `enabled_features`: contains all features that are not allowed to be used.
        Some features might be blacklisted because e.g. Tofino does not support them.
        The relative order of the features is preserved in the returned subset.
        """
        return [x for x in Feature if x not in self.enabled_features]

    @staticmethod
    def create_for_switch(switch: SwitchConstants) -> 'ModelTrainingConfig':
        """Creates a config based on the given switch constants, e.g. random forest parameters."""
        enabled_features = [Feature.LENGTH_MAX, Feature.LENGTH_SUM, Feature.COUNT_TCP_SYN, Feature.COUNT_TCP_ACK,
                            Feature.COUNT_TCP_RST, Feature.PORT_CLIENT, Feature.PORT_SERVER, Feature.LENGTH_CURRENT]

        # The following values were calculated using bayesian optimization
        if switch.dt_per_rf_count == 6 and switch.max_dt_depth == 7 and switch.max_rf_count == 8:
            return ModelTrainingConfig(
                    classification_certainty_threshold=0.766,
                    rf_score_threshold_old_over_new=0.681,
                    rf_score_threshold_new=0.296,
                    rf_score_threshold_old_over_none=0.992,
                    rf_score_penalize_below_classified_ratio=0.501,
                    rf_max_n_estimators=switch.dt_per_rf_count,
                    rf_max_max_depth=switch.max_dt_depth,
                    max_rf_count=switch.max_rf_count,
                    max_classifiable_flow_length=switch.max_classifiable_flow_length,
                    enabled_features=enabled_features
            )
        elif switch.dt_per_rf_count == 3 and switch.max_dt_depth == 5 and switch.max_rf_count == 6:
            return ModelTrainingConfig(
                    classification_certainty_threshold=0.662,
                    rf_score_threshold_old_over_new=1.000,
                    rf_score_threshold_new=0.402,
                    rf_score_threshold_old_over_none=0.259,
                    rf_score_penalize_below_classified_ratio=0.000,
                    rf_max_n_estimators=switch.dt_per_rf_count,
                    rf_max_max_depth=switch.max_dt_depth,
                    max_rf_count=switch.max_rf_count,
                    max_classifiable_flow_length=switch.max_classifiable_flow_length,
                    enabled_features=enabled_features
            )
        elif switch.dt_per_rf_count == 2 and switch.max_dt_depth == 5 and switch.max_rf_count == 6:
            return ModelTrainingConfig(
                    classification_certainty_threshold = 0.886,
                    rf_score_threshold_old_over_new = 0.499,
                    rf_score_threshold_new = 0.513,
                    rf_score_threshold_old_over_none = 0.815,
                    rf_score_penalize_below_classified_ratio = 0.312,
                    rf_max_n_estimators=switch.dt_per_rf_count,
                    rf_max_max_depth=switch.max_dt_depth,
                    max_rf_count=switch.max_rf_count,
                    max_classifiable_flow_length=switch.max_classifiable_flow_length,
                    enabled_features=enabled_features
            )
        else:
            raise ValueError(f"Unsupported input: {switch}")

    @staticmethod
    def create_for_centralized() -> 'ModelTrainingConfig':
        """Creates a config for the centralized component, which does not suffer from data plane limitations."""
        # The following values were calculated using bayesian optimization
        return ModelTrainingConfig(
                classification_certainty_threshold = 0.800,
                rf_score_threshold_old_over_new = 0.999,
                rf_score_threshold_new = 0.000,
                rf_score_threshold_old_over_none = 0.999,
                rf_score_penalize_below_classified_ratio = 0.000,
                rf_max_n_estimators=16,
                rf_max_max_depth=16,
                max_rf_count=32,
                max_classifiable_flow_length=32,
                enabled_features=[f for f in Feature if f not in Feature.time_based_features()]
        )


@dataclasses.dataclass(frozen=True)
class ModelRF:
    """Represents a single random forest: a collection of decision trees."""

    trained_on_flow_length: int
    """The flow packet count on which this random forest was trained on."""

    classifier: RandomForestClassifier
    """The random forest itself."""

    @property
    def dts(self) -> List[DecisionTreeClassifier]:
        """Returns the decision trees within this random forest."""
        return self.classifier.estimators_

    @property
    def complexity(self) -> int:
        """Calculates the complexity of this model, which is based on e.g. the number of nodes in the decision trees."""
        return sum(dt.tree_.node_count for dt in self.dts)


@dataclasses.dataclass(frozen=True)
class Model:
    """
    Represents an ML model: a collection of random forest, each mapped to various flow lengths.

    Each RF has a unique identifier. The ID of '0' is reserved; it stands for the lack of a random forest.
    """

    flow_length_to_id: Dict[int, int]
    """
    The random forest identifiers mapped by the flow length at which they should be used.
    Not all flow lengths have a random forest associated with them.
    """

    id_to_rf: Dict[int, ModelRF]
    """Maps random forest identifiers to the random forest instances."""

    @staticmethod
    def no_rf_id() -> int:
        """Returns the identifier used to represent the lack of a random forest."""
        return 0

    @property
    def complexity(self) -> int:
        """Calculates the complexity of this model, which is based on e.g. the number of nodes in the decision trees."""
        return sum(rf.complexity for rf in self.id_to_rf.values())

    @property
    def id_to_flow_lengths(self) -> Dict[int, List[int]]:
        """Calculates the inverse mapping of flow lengths to random forest identifiers."""
        result = dict()
        for flow_length, rf_id in self.flow_length_to_id.items():
            result[rf_id] = result.get(rf_id, []) + [flow_length]
        return result


@dataclasses.dataclass(frozen=True)
class ModelRFSlice:
    """Stores a subset of the decision trees of a random forest."""

    original: ModelRF
    """The original random forest from which the slice was created."""

    dts: List[DecisionTreeClassifier]
    """The decision trees that are part of this slice."""

    dt_indexes: List[int]
    """The indexes of the decision trees in the original random forest."""

    @property
    def dts_and_indexes(self) -> List[Tuple[int, DecisionTreeClassifier]]:
        """The decision trees that are part of this slice and their index in the original random forest."""
        return [(i, dt) for i, dt in zip(self.dt_indexes, self.dts)]


@dataclasses.dataclass(frozen=True)
class ModelSlice:
    """
    Represents a sliced ML model: each RF in the model is sliced, meaning they all only contain a subset of the DTs.
    A slice contains the same subset of DTs for all RFs, e.g. the first N DTs of each RF.
    """

    original: Model
    """The original model from which the slice was created."""

    id_to_rf: Dict[int, ModelRFSlice]
    """Maps RF identifiers to the random forest slices."""

    @property
    def flow_length_to_id(self) -> Dict[int, int]:
        """Proxies to the original model, because the RF IDs are the same."""
        return self.original.flow_length_to_id

    @property
    def id_to_flow_lengths(self) -> Dict[int, List[int]]:
        """Proxies to the original model, because the RF IDs are the same."""
        return self.original.id_to_flow_lengths
