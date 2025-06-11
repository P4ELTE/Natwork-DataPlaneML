import logging
import math
from typing import Dict

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.utils import compute_sample_weight

from lib_common.flow import Feature, FlowDataCols, FlowPredCols, Label, ListOfFeaturesSchema, ListOfFlowDataSchema, \
    ListOfFlowPredSchema, ListOfLabelSchema
from lib_common.model.classifier import calculate_classifiable_flows_mask, classify_flows_with_rf
from lib_common.model.data import Model, ModelRF, ModelTrainingConfig
from lib_common.model.score import calculate_f1_score_excluding_not_set
from lib_common.utils import PerfReporter

_logger = logging.getLogger(__name__)


def train_model(config: ModelTrainingConfig, flow_data: ListOfFlowDataSchema,
                flow_features: ListOfFeaturesSchema, flow_true_labels: ListOfLabelSchema) -> Model:
    """
    Trains a new model containing multiple RFs from scratch using the given data.
    This method internally handles when time-based features are disabled.
    """

    perf_report = PerfReporter.millis(1, _logger, "model training")
    perf_report.start()

    _logger.info(f"Training new model on {len(flow_data)} flows"
                 f" (Label stats: {Label.compute_count_statistics(flow_true_labels)})")

    # If time-based features are disabled, set all of their values to 0, therefore the RFs won't use them
    if not config.use_time_based_features:
        _logger.info(f"Time-based features are disabled, setting their values to 0: {Feature.time_based_features()}")
        flow_features = np.copy(flow_features)
        for feature in Feature.time_based_features():
            flow_features[:, :, feature.value] = 0

    # Some additional features might be disabled
    if len(Feature.disabled_features()) > 0:
        _logger.info(f"Some features are disabled, setting their values to 0: {Feature.disabled_features()}")
        flow_features = np.copy(flow_features)
        for feature in Feature.disabled_features():
            flow_features[:, :, feature.value] = 0

    # Flows are classified during training: we need to know which flows should be used for training subsequent RFs,
    #   as already classified flows should not be used, because they won't be classified by these subsequent RFs.
    #   This variable is used to store the predictions of the RFs for each flow.
    predictions: ListOfFlowPredSchema = np.zeros((len(flow_data), len(FlowPredCols)), dtype=np.uint32)

    flow_length_to_rf_id: Dict[int, int] = dict()
    id_to_rf: Dict[int, ModelRF] = dict()

    for flow_length in range(1, config.max_classifiable_flow_length + 1):
        # Determine which flows to consider for training the next RF
        mask = calculate_classifiable_flows_mask(flow_data, predictions, flow_length)

        # Stop if no unclassified flows are found
        if not mask.any():
            _logger.info(f"Stopping at {len(id_to_rf)} RFs: no unclassified flows with length >= {flow_length} found")
            break

        old_score, old_rf_id = math.nan, None
        try:
            # Try to reuse one of the previous RFs (the best one)
            for rf_id, rf in id_to_rf.items():
                score = _calculate_rf_score(config, flow_length, rf, flow_data,
                                            flow_features, flow_true_labels, predictions, mask)
                if old_score is math.nan or old_score < score:
                    old_score, old_rf_id = score, rf_id
            if old_score > config.rf_score_threshold_old_over_new:
                rel_i = -1 * (len(id_to_rf) - old_rf_id + 1)
                _logger.info(f"Flow length {flow_length}: reusing RF[{rel_i}] (no need for new)"
                             f" (score: {old_score:.2f})")
                flow_length_to_rf_id[flow_length] = old_rf_id
                continue

            # Don't try to add a new RF if the maximum number of RFs has been reached
            if len(id_to_rf) >= config.max_rf_count:
                _logger.info(f"Flow length {flow_length}: can't use old RF (score: {old_score:.2f})"
                             f" and can't add new RF (reached maximum RF count)")
                continue

            # Create training and testing sub-mask randomly, with X% for training and (1-X%) for testing
            mask_idx = np.where(mask)[0]
            if config.rf_train_test_split > 0 and len(mask_idx) > 10:  # Only if the split is enabled
                np.random.shuffle(mask_idx)
                train_test_split = int(len(mask_idx) * config.rf_train_test_split)
                train_idx, test_idx = np.zeros_like(mask), np.zeros_like(mask)
                train_idx[mask_idx[:train_test_split]] = True
                test_idx[mask_idx[train_test_split:]] = True
            else:
                train_idx, test_idx = mask, mask

            # Try to train and add a new RF
            new_rf_id = len(id_to_rf) + 1
            new_rf = _train_single_rf(config, flow_length, flow_features[train_idx, flow_length - 1],
                                      flow_data[train_idx], flow_true_labels[train_idx])
            new_score = _calculate_rf_score(config, flow_length, new_rf, flow_data,
                                            flow_features, flow_true_labels, predictions, test_idx)
            if new_score > config.rf_score_threshold_new:
                _logger.info(f"Flow length {flow_length}: adding new RF"
                             f" (scores: old={old_score:.2f}; new={new_score:.2f})")
                flow_length_to_rf_id[flow_length] = new_rf_id
                id_to_rf[new_rf_id] = new_rf
            else:
                _logger.info(f"Flow length {flow_length}: ignoring new RF"
                             f" (scores: old={old_score:.2f}; new={new_score:.2f})")
        finally:  # Execute some actions even if 'continue' is used
            # Try to use a previous RF again (with different threshold) if no RF is mapped to the current flow length
            if (flow_length not in flow_length_to_rf_id
                    and old_score > config.rf_score_threshold_old_over_none):
                rel_i = -1 * (len(id_to_rf) - old_rf_id + 1)
                _logger.info(f"Flow length {flow_length}: reusing RF[{rel_i}] (instead of no RF)"
                             f" (score: {old_score:.2f})")
                flow_length_to_rf_id[flow_length] = old_rf_id
                continue

            # Try to classify flows
            rf = id_to_rf.get(flow_length_to_rf_id.get(flow_length, 0), None)
            if rf is not None:
                classify_flows_with_rf(config.classification_certainty_threshold, flow_length, rf, flow_data,
                                       flow_features, predictions, mask)

    perf_report.stop()
    model = Model(flow_length_to_id=flow_length_to_rf_id, id_to_rf=id_to_rf)
    return model


def _calculate_rf_score(config: ModelTrainingConfig, flow_length: int, rf: ModelRF, flow_data: ListOfFlowDataSchema,
                        flow_features: ListOfFeaturesSchema, flow_true_labels: ListOfLabelSchema,
                        predictions: ListOfFlowPredSchema, classifiable_mask: np.ndarray) -> float:
    """
    Calculates how well the specified RF classifies the flows at the given length.

    The predictions array is used to temporarily store the predicted labels.
    It should equal the not set label wherever the mask is true, in which case it will remain unchanged.
    """
    classify_flows_with_rf(config.classification_certainty_threshold, flow_length, rf, flow_data, flow_features,
                           predictions, classifiable_mask)
    y_pred = predictions[:, FlowPredCols.PREDICTED_LABEL]
    y_pred = y_pred[classifiable_mask]
    y_true = flow_true_labels[classifiable_mask]
    return _calculate_f1_score_with_modifiers(y_true, y_pred, config)


def _calculate_f1_score_with_modifiers(y_true: np.ndarray, y_pred: np.ndarray, config: ModelTrainingConfig) -> float:
    """Applies various score modifiers, e.g. penalizing low classified flow ratios."""
    score = calculate_f1_score_excluding_not_set(y_true, y_pred, 0)

    # Penalize the score if the RF classified too few flows
    classified_ratio = np.count_nonzero(y_pred != Label.NOT_SET) / len(y_pred)
    if classified_ratio < config.rf_score_penalize_below_classified_ratio:
        score *= classified_ratio / config.rf_score_penalize_below_classified_ratio

    return score


def _train_single_rf(config: ModelTrainingConfig, flow_length: int, flow_features: ListOfFeaturesSchema,
                     flow_data: ListOfFlowDataSchema, flow_true_labels: ListOfLabelSchema) -> ModelRF:
    """Trains a single RF using the given features and labels."""

    # Weigh labels. Benign labels are more important: it's okay to miss an attack, but not to block benign traffic.
    class_bin_counts = np.bincount(flow_true_labels - 1, minlength=len(Label) - 1)  # Excluding the not set label
    class_bin_counts = np.maximum(class_bin_counts, 1)  # Avoid division by zero (if a class is missing)
    class_weights = len(flow_true_labels) / (len(flow_true_labels) * class_bin_counts)
    class_weights = {l.value: class_weights[l.value - 1] for l in Label.excluding_not_set()}
    class_weights[Label.BENIGN.value] *= config.rf_benign_label_weight
    weights = compute_sample_weight(class_weights, flow_true_labels)

    # Apply extra weight to newer flows
    times = flow_data[:, FlowDataCols.LAST_SEEN_MS]
    time_min, time_max = np.min(times), np.max(times)
    if time_max > time_min:  # Avoid division by zero
        norm_times = (times - time_min) / (time_max - time_min)  # Normalized to [0, 1]
        # Exponential weighting
        if config.rf_age_weight_exp_base > 1 and time_max > time_min:
            weights *= config.rf_age_weight_exp_base ** norm_times  # Oldest: weight*1; Newest: weight*base
        # Linear weighting
        if config.rf_age_weight_lerp_max > 1:
            weights *= (1 - norm_times) * 1 + norm_times * config.rf_age_weight_lerp_max

    # Base model without hyperparameter optimization (used as comparison baseline if optimization is enabled)
    base_classifier = RandomForestClassifier(n_estimators=config.rf_max_n_estimators,
                                             max_depth=config.rf_max_max_depth,
                                             min_samples_split=config.rf_split_min_samples,
                                             min_samples_leaf=config.rf_node_min_samples,
                                             random_state=config.random_seed)
    base_classifier.fit(flow_features, flow_true_labels, weights)

    # Skip hyperparameter optimization if it's disabled, saving time
    if not config.rf_hyperopt_enabled:
        return ModelRF(trained_on_flow_length=flow_length, classifier=base_classifier)

    # Custom scorer that handled the not set label and other custom score modifiers
    def custom_scorer(estimator, x, y_true) -> float:
        y_pred = estimator.predict(x)
        score = _calculate_f1_score_with_modifiers(y_true, y_pred, config)
        score -= config.rf_hyperopt_penalty_n_estimators * (estimator.n_estimators / config.rf_max_n_estimators)
        score -= config.rf_hyperopt_penalty_max_depth * (estimator.max_depth / config.rf_max_max_depth)
        return score

    # Hyperparameter search space
    import skopt
    param_space = {
        # 'n_estimators': skopt.space.Integer(2, config.rf_max_n_estimators),
        'n_estimators': [config.rf_max_n_estimators],  # TODO We don't actually support a smaller value yet
        'max_depth': skopt.space.Integer(3, config.rf_max_max_depth),
        'min_samples_split': [config.rf_split_min_samples],
        'min_samples_leaf': [config.rf_node_min_samples]
    }

    # Bayesian optimization
    classifier = RandomForestClassifier(random_state=config.random_seed)
    opt = skopt.BayesSearchCV(classifier, param_space, n_iter=config.rf_hyperopt_iterations,
                              cv=config.rf_hyperopt_cv_folds, random_state=config.random_seed,
                              scoring=custom_scorer)
    opt.fit(flow_features, flow_true_labels, sample_weight=weights)

    # Construct the optimized classifier
    classifier = RandomForestClassifier(**opt.best_params_, random_state=config.random_seed)
    classifier.fit(flow_features, flow_true_labels, weights)

    # Compare the optimized classifier to the baseline
    base_score = custom_scorer(base_classifier, flow_features, flow_true_labels)
    optimized_score = custom_scorer(classifier, flow_features, flow_true_labels)
    _logger.info(f"RF F1 scores: base={base_score:.2f}; optimized={optimized_score:.2f}"
                 f" ({100 * optimized_score / base_score:.2f}%);"
                 f" params={dict(opt.best_params_)}")

    return ModelRF(trained_on_flow_length=flow_length, classifier=classifier)
