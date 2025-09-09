import argparse
import logging
import sys
from pathlib import Path
from typing import Tuple

import joblib
import numpy as np
from sklearn.model_selection import train_test_split

from lib_common.data import SwitchConstants
from lib_common.flow import FlowPredCols
from lib_common.model.classifier import classify_flows_with_model
from lib_common.model.data import Model, ModelTrainingConfig
from lib_common.model.export import visualize_model
from lib_common.model.score import calculate_accuracy_not_set_is_benign, calculate_f1_score_not_set_is_benign
from lib_common.model.trainer import train_model

_logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', choices=['debug', 'info'], default='info')
    parser.add_argument('--data-path', type=Path, required=True,
                        help="Path of the file containing the data exported by the controller; to be used for training")
    parser.add_argument('--model-path', type=Path, required=True,
                        help="Path where the trained model should be saved")
    parser.add_argument('--overwrite', action='store_true',
                        help="If set, the model at --model-path will be overwritten if it already exists")
    parser.add_argument('--constraints-type', choices=['ebpf', 'tofino', 'centralized'], required=True,
                        help="What constraints should be considered during training")
    parser.add_argument('--train-ratio', type=float, default=0.5,
                        help="Fraction of the data to be used for training")
    args = parser.parse_args()

    logging.basicConfig(force=True, level=args.log_level.upper(),
                        format='[%(asctime)s] %(levelname)s [%(threadName)s] [%(name)s] %(message)s',
                        stream=sys.stdout)
    logging.getLogger("matplotlib").setLevel(logging.WARNING)

    data_path: Path = args.data_path
    model_path: Path = args.model_path
    train_ratio: float = args.train_ratio

    training_config: ModelTrainingConfig = {
        'ebpf': lambda: ModelTrainingConfig.create_for_switch(SwitchConstants.create_ebpf()),
        'tofino': lambda: ModelTrainingConfig.create_for_switch(SwitchConstants.create_tofino()),
        'centralized': lambda: ModelTrainingConfig.create_for_centralized(),
    }[args.constraints_type]()

    start_trainer(data_path, model_path, args.overwrite, training_config, train_ratio)


def start_trainer(data_path: Path, model_path: Path, model_path_overwrite_enabled: bool,
                  training_config: ModelTrainingConfig, train_ratio: float) -> None:
    """Starts the trainer component."""
    if not data_path.exists():
        _logger.error(f"Input data file '{data_path}' does not exist, aborting...")
        sys.exit(1)

    model_path.parent.mkdir(parents=True, exist_ok=True)
    if model_path.exists() and not model_path_overwrite_enabled:
        _logger.error(f"Output model file '{model_path}' already exists, aborting...")
        sys.exit(1)

    loaded_data = load_data(data_path, training_config)
    model, score_f1, score_acc = execute_training(loaded_data, training_config, train_ratio)

    model_info = f"""
    F1 score: {score_f1:.4f}
    Accuracy: {score_acc:.4f}
    Complexity: {model.complexity}
    Number of RFs: {len(model.id_to_rf)}
    Classifiable flow lengths: {sorted(model.flow_length_to_id.keys())}
    Enabled features: {', '.join(feature.name for feature in training_config.enabled_features)}"""

    _logger.info("Training has finished, information about the model: " + model_info)

    joblib.dump(model, model_path)
    visualize_model(model, 'pre-trained', model_path.with_suffix('.pdf'), model_info)
    _logger.info(f"The model has been saved to {model_path}")


def load_data(data_path: Path, training_config: ModelTrainingConfig) -> tuple:
    """
    Loads data from the format exported by the controller.
    Returns a tuple containing the flow data, flow features and flow true labels.
    """
    _logger.info(f"Loading data from {data_path}...")
    with np.load(data_path) as data:
        flow_data = data['flow_data']
        flow_features = data['flow_features']
        flow_true_labels = data['flow_true_labels']

    for feature in training_config.disabled_features:
        flow_features[:, :, feature.value] = 0

    _logger.info(f"Loaded {len(flow_data)} flows")
    return flow_data, flow_features, flow_true_labels


def execute_training(loaded_data: tuple, config: ModelTrainingConfig,
                     train_ratio: float) -> Tuple[Model, float, float]:
    """Trains a model based on the loaded data."""
    _logger.info(f"Starting training with train-test split of {train_ratio} training ratio...")

    flow_data, flow_features, flow_true_labels = loaded_data
    split = train_test_split(flow_data, flow_features, flow_true_labels, train_size=train_ratio)
    flow_data_train, flow_features_train, flow_true_labels_train = split[0], split[2], split[4]
    flow_data_test, flow_features_test, flow_true_labels_test = split[1], split[3], split[5]

    model: Model = train_model(config, flow_data_train, flow_features_train, flow_true_labels_train)
    pred = classify_flows_with_model(config.classification_certainty_threshold, model,
                                     flow_data_test, flow_features_test)
    score_f1 = calculate_f1_score_not_set_is_benign(flow_true_labels_test, pred[:, FlowPredCols.PREDICTED_LABEL])
    score_acc = calculate_accuracy_not_set_is_benign(flow_true_labels_test, pred[:, FlowPredCols.PREDICTED_LABEL])
    return model, score_f1, score_acc


if __name__ == '__main__':
    main()
