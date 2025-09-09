import logging
import os
import pickle
import time
from pathlib import Path
from typing import List, Literal, Optional, Tuple

import numpy as np
import psutil

from lib_common.control_plane import monitoring, traffic_forwarding
from controller.model_encoding import ModelEncoder, create_model_encoder
from controller.data import ControllerConfig, ModelRefiningConfig
from lib_common.control_plane.data import Network
from controller.interface import CoordinatorInterface, CoordinatorInterfaceHandler, OracleInterface
from controller.stats import StatsManager
from lib_common.flow import FlowDataCols, FlowPredCols, Label, ListOfFeaturesSchema, ListOfFlowDataSchema, \
    ListOfFlowPredSchema, ListOfLabelSchema
from lib_common.model.classifier import classify_flows_with_model
from lib_common.model.data import Model, ModelTrainingConfig
from lib_common.model.export import visualize_model_nonblocking
from lib_common.model.score import calculate_f1_score_not_set_is_benign
from lib_common.model.trainer import train_model
from p4_api_bridge import SwitchApiError

from controller.reporting import ReportingAPI

_logger = logging.getLogger(__name__)


class RecentFlowStorage:
    """Part of the controller logic responsible for storing the recent flow data and features."""

    def __init__(self, start_time_ms: int, min_flow_count: int, keep_flows_time_window_sec: int) -> None:
        self._start_time_ms: int = start_time_ms
        self._min_flow_count: int = min_flow_count
        self._keep_flows_time_window_sec: int = keep_flows_time_window_sec
        # We don't want to hardcode the shape and dtype here, so let's late-init
        self._recent_flow_data: Optional[ListOfFlowDataSchema] = None
        self._recent_flow_features: Optional[ListOfFeaturesSchema] = None
        self._recent_flow_pred: Optional[ListOfFlowPredSchema] = None
        self._recent_flow_true_labels: Optional[ListOfLabelSchema] = None
        self._ongoing_flow_data: Optional[ListOfFlowDataSchema] = None
        self._ongoing_flow_features: Optional[ListOfFeaturesSchema] = None
        self._ongoing_flow_pred: Optional[ListOfFlowPredSchema] = None
        self._ongoing_flow_true_labels: Optional[ListOfLabelSchema] = None

    def add_new_flows(self, flow_data: ListOfFlowDataSchema, flow_features: ListOfFeaturesSchema,
                      flow_pred: ListOfFlowPredSchema, flow_true_labels: ListOfLabelSchema) -> None:
        """Stores the recently collected flows."""
        if self._recent_flow_data is None:
            self._recent_flow_data, self._recent_flow_features = flow_data, flow_features
            self._recent_flow_pred, self._recent_flow_true_labels = flow_pred, flow_true_labels
        else:
            self._recent_flow_data = np.concatenate((self._recent_flow_data, flow_data))
            self._recent_flow_features = np.concatenate((self._recent_flow_features, flow_features))
            self._recent_flow_pred = np.concatenate((self._recent_flow_pred, flow_pred))
            self._recent_flow_true_labels = np.concatenate((self._recent_flow_true_labels, flow_true_labels))

    def forget_old_flows(self) -> None:
        """Removes the flows which are too old from the storage."""
        cutoff_time_ms = time.time_ns() // 1_000_000 - self._start_time_ms - self._keep_flows_time_window_sec * 1_000
        recent_mask = self._recent_flow_data[:, FlowDataCols.LAST_SEEN_MS] > cutoff_time_ms
        self._recent_flow_data = self._recent_flow_data[recent_mask]
        self._recent_flow_features = self._recent_flow_features[recent_mask]
        self._recent_flow_pred = self._recent_flow_pred[recent_mask]
        self._recent_flow_true_labels = self._recent_flow_true_labels[recent_mask]
        _logger.info(f"Old flows were removed from recent flows; new size: {len(self._recent_flow_data)}")

    def set_ongoing_flows(self, flow_data: ListOfFlowDataSchema, flow_features: ListOfFeaturesSchema,
                          flow_pred: ListOfFlowPredSchema, flow_true_labels: ListOfLabelSchema) -> None:
        """Stores the ongoing flows, overwriting any previously stored values.
        Some methods return the ongoing flows in additional to the recent flows."""
        self._ongoing_flow_data, self._ongoing_flow_features = flow_data, flow_features
        self._ongoing_flow_pred, self._ongoing_flow_true_labels = flow_pred, flow_true_labels

    def count(self) -> int:
        """Returns the number of flows stored in the recent flow storage. Ongoing flows are not counted."""
        return len(self._recent_flow_data)

    def get_flows_last_n_sec(self, last_n_sec: int) -> Optional[Tuple[ListOfFlowDataSchema,
    ListOfFeaturesSchema, ListOfFlowPredSchema, ListOfLabelSchema]]:  # noqa
        """Gets the recent flows that were seen in the last N seconds.
        If there aren't enough flows in the last N seconds, then this filter is relaxed to include enough.
        If there are still not enough flows, then None is returned.
        Ongoing flows are included in the result, but aren't included in the count/filter relaxation.
        """

        # If there aren't enough flows, return nothing
        if self._recent_flow_data is None or len(self._recent_flow_data) < self._min_flow_count:
            return None

        # Obey the last_n_sec limit
        cutoff_time_ms = time.time_ns() // 1_000_000 - self._start_time_ms - last_n_sec * 1_000
        mask = self._recent_flow_data[:, FlowDataCols.LAST_SEEN_MS] > cutoff_time_ms

        # If there aren't enough flows, keep the most recent ones, returning the required minimum amount
        if np.sum(mask) < self._min_flow_count:
            ordered_last_seen = np.argsort(self._recent_flow_data[:, FlowDataCols.LAST_SEEN_MS])
            mask = np.zeros_like(mask)
            mask[ordered_last_seen[-self._min_flow_count:]] = True

        return np.concatenate((self._recent_flow_data[mask], self._ongoing_flow_data)), \
            np.concatenate((self._recent_flow_features[mask], self._ongoing_flow_features)), \
            np.concatenate((self._recent_flow_pred[mask], self._ongoing_flow_pred)), \
            np.concatenate((self._recent_flow_true_labels[mask], self._ongoing_flow_true_labels))


class ModelRefiner:
    """Part of the controller logic responsible for refining the model based on the collected flow data."""

    def __init__(self, start_time_ms: int, output_dir: Path,
                 training_config: ModelTrainingConfig, refining_config: ModelRefiningConfig) -> None:
        self.start_time_ms: int = start_time_ms
        self._output_dir: Path = output_dir
        self._training_config: ModelTrainingConfig = training_config
        self._refining_config: ModelRefiningConfig = refining_config

    def get_actual_model_score(self, flow_pred: ListOfFlowPredSchema, flow_true_labels: ListOfLabelSchema) -> float:
        """Calculates the score of the classification that was done in the data plane."""
        return calculate_f1_score_not_set_is_benign(flow_true_labels, flow_pred[:, FlowPredCols.PREDICTED_LABEL])

    def get_estimated_model_score(self, model: Model, flow_data: ListOfFlowDataSchema,
                                  flow_features: ListOfFeaturesSchema, flow_true_labels: ListOfLabelSchema) -> float:
        """Determines the estimated score of the model on the specified flows."""
        pred = classify_flows_with_model(self._training_config.classification_certainty_threshold,
                                         model, flow_data, flow_features)

        # Newer flows should have more weight
        times = flow_data[:, FlowDataCols.LAST_SEEN_MS]
        time_min, time_max = np.min(times), np.max(times)
        if self._refining_config.scoring_flow_age_weight_lerp_max > 1 and time_max > time_min:  # Avoid division by zero
            norm_times = (times - time_min) / (time_max - time_min)  # Normalized to [0, 1]
            weights = (1 - norm_times) * 1 + norm_times * self._refining_config.scoring_flow_age_weight_lerp_max
        else:
            weights = None

        return calculate_f1_score_not_set_is_benign(flow_true_labels, pred[:, FlowPredCols.PREDICTED_LABEL],
                                                    weight=weights)

    def is_model_refinement_necessary(self, current_score: float) -> bool:
        """Determines whether the current model needs to be improved (because it doesn't perform well enough)."""
        if current_score >= self._refining_config.target_latest_flow_f1_score:
            _logger.info(f"F1 score is {current_score:.2f}; no re-training necessary")
            return False
        else:
            _logger.info(f"F1 score is {current_score:.2f}; model refinement needed")
            return True

    def refine_model(self, flow_data: ListOfFlowDataSchema, flow_features: ListOfFeaturesSchema,
                     flow_true_labels: ListOfLabelSchema) -> Model:
        """Improves the current model: creates a new model that might be better than the current one."""
        return train_model(self._training_config, flow_data, flow_features, flow_true_labels)

    def visualize_model(self, model: Model, score: float, flow_true_labels: ListOfLabelSchema,
                        model_accepted: bool) -> None:
        """
        Visualizes a model, saving the graphics to the output directory.
        This method also takes the model training data, the model's score as input,
        and whether the new model has been accepted as input.
        """
        first_page = f"""
                Estimated F1 score: {score:.2f}
                Accepted: {model_accepted}
        
                Training data:
                - Flow count: {len(flow_true_labels)}
                - Label stats: {Label.compute_count_statistics(flow_true_labels)}
                """
        millis_since_start = time.time_ns() // 1_000_000 - self.start_time_ms
        time_id = f'{millis_since_start // 1000:04d}s_{millis_since_start % 1000:03d}ms'
        identifier = f'{time_id}_F1-{round(score * 100)}'
        save_path = self._output_dir / 'models' / f'model_{identifier}.pdf'
        visualize_model_nonblocking(model, identifier, save_path, first_page)

    def is_new_model_acceptable(self, old_score: float, new_score: float) -> bool:
        """Determines whether the new model should be preferred over the old one."""
        _logger.info(f"F1 score with new model: {new_score:.2f} (old model: {old_score:.2f})")
        if new_score >= self._refining_config.target_latest_flow_f1_score:
            _logger.info("New model performance acceptable; sending it to the coordinator")
            return True
        elif new_score >= old_score + self._refining_config.acceptable_f1_score_difference:
            _logger.info("New model performance below target, but much better than the old model;"
                         "sending it to the coordinator")
            return True
        else:
            _logger.info("New model performance not acceptable; not sending it to the coordinator")
            return False


class ControllerLogic(CoordinatorInterfaceHandler):
    """
    Main class for the switch controller. It is responsible for connecting all aspects of the controller component.
    """

    def __init__(self, start_time_ms: int, output_dir: Path, config: ControllerConfig, network: Network,
                 oracle_interface: OracleInterface, coordinator_interface: CoordinatorInterface,
                 model: Model, stats: StatsManager, expected_packet_count: Optional[int]) -> None:
        self._start_time_ms: int = start_time_ms
        self._shutdown: bool = False
        self._output_dir: Path = output_dir
        self._config: ControllerConfig = config
        self._network: Network = network
        self._oracle_interface: OracleInterface = oracle_interface
        self._coordinator_interface: CoordinatorInterface = coordinator_interface
        self._model: Model = model
        self._stats: StatsManager = stats
        self._expected_packet_count: Optional[int] = expected_packet_count
        self._model_encoder: ModelEncoder = create_model_encoder(config.switch, network.controlled_switches,
                                                                 config.training)
        self._monitoring_api: ReportingAPI = ReportingAPI(start_time_ms, config.switch,
                                                          network.controlled_switches,
                                                          config.refining.flow_timeout_sec)
        self._recent_flows: RecentFlowStorage = RecentFlowStorage(start_time_ms, config.refining.min_recent_flow_count,
                                                                  config.refining.max_of_flow_time_window_sec)
        self._refiner: ModelRefiner = ModelRefiner(start_time_ms, output_dir, config.training, config.refining)
        self._deployed_models: List[Tuple[Model, int, int]] = []  # (model, active_since_ms, active_until_ms)
        # During the model switchover period neither the old, nor the new model is considered active in this list

    def initialize_switches(self) -> None:
        """
        Initializes the switches:
        - Sets up the forwarding rules
        - Uploads the model
        - Configures monitoring
        """
        _logger.info(f"Initializing switches managed by this controller instance: "
                     f"{', '.join((x.name for x in self._network.controlled_switches))}")

        traffic_forwarding.configure_forwarding(self._network)
        self._model_encoder.load_model(self._model, self._config.training.classification_certainty_threshold)
        flow_report_ratio = 1.0 if self._config.stats_from_all_flows else self._config.monitored_flow_ratio
        monitoring.configure_reporting(self._config.switch, self._network, flow_report_ratio)

    def shutdown(self) -> None:
        """Signals the controller to shut down."""
        _logger.info("Shutting down...")
        self._shutdown = True
        self._coordinator_interface.shutdown()
        self._monitoring_api.shutdown()
        self._model_encoder.abort()

        # Log approximately how many report packets got dropped
        if self._expected_packet_count is not None:
            actual, expected = self._monitoring_api.received_report_count, self._expected_packet_count
            _logger.warning(f"Report packet counts:"
                            f" expected={expected}; actual={actual};"
                            f" diff={abs(expected - actual)} ({100 * abs(expected - actual) / expected:.2f}%)")

        # Log how many flows had to be invalidated due to hash collisions, dropped report packets or other issues
        if self._monitoring_api.flow_count_with_invalid_features != (0, 0):
            start, mid = self._monitoring_api.flow_count_with_invalid_features
            total = start + mid
            _logger.warning(f"Flows with invalid features: since_first_packet={start}; issue_while_ongoing={mid};"
                            f" total={total} ({100 * total / self._monitoring_api.total_flow_count:.2f}%)")

        # Export the recent flows
        if self._config.export_monitoring_data and (data := self._recent_flows.get_flows_last_n_sec(99999)) is not None:
            flow_data, flow_features, flow_pred, flow_true_labels = data
            np.savez_compressed(self._output_dir / 'monitored_flows.npz', flow_data=flow_data,
                                flow_features=flow_features, flow_pred=flow_pred, flow_true_labels=flow_true_labels)

        # Export the deployed models
        if self._deployed_models:  # First, fix the last timestamp
            old_model, old_active_since_ms, _ = self._deployed_models[-1]
            current_ms = time.time_ns() // 1_000_000 - self._start_time_ms
            self._deployed_models[-1] = (old_model, old_active_since_ms, current_ms)
        with (self._output_dir / 'deployed_models.pickle').open('wb') as f:
            # noinspection PyTypeChecker
            pickle.dump(self._deployed_models, f)

    def run_monitoring_listener_loop(self) -> None:
        """Starts listening for and processing report packets sent by the switches. This method blocks indefinitely."""
        _logger.info("Entering monitoring listener loop...")
        self._monitoring_api.listen_for_report_packets_forever()

    def handle_model_update(self, model: Model) -> None:
        _logger.info(f"Model update received: {model}")
        deployment_started_ms = time.time_ns() // 1_000_000 - self._start_time_ms

        if self._deployed_models:  # Set the end time of the previous model
            old_model, old_active_since_ms, _ = self._deployed_models[-1]
            self._deployed_models[-1] = (old_model, old_active_since_ms, deployment_started_ms)

        try:
            self._model = model
            self._model_encoder.load_model(model, self._config.training.classification_certainty_threshold)
        except SwitchApiError as e:
            if self._shutdown:
                _logger.info(f"Model encoding failed, probably due to shutdown; ignoring\n"
                             f"Ignored error: {type(e).__name__}: {e}")
            else:
                raise

        deployment_ended_ms = time.time_ns() // 1_000_000 - self._start_time_ms
        self._deployed_models.append((model, deployment_ended_ms, -1))  # Save the start time of the new model
        self._stats.register_model_deployment(deployment_ended_ms - deployment_started_ms, model)

    def run_main_loop(self) -> None:
        """
        Starts the main logic loop responsible for:
        - listening for and handling requests/commands from the coordinator
        - periodically checking the model performance
        - refining the model if necessary and sending it to the coordinator

        This method blocks indefinitely.
        """
        _logger.debug("Initializing outbound interfaces...")
        self._oracle_interface.initialize()
        self._coordinator_interface.initialize()

        _logger.info("Entering main loop...")
        this_proc = psutil.Process(os.getpid())
        while not self._shutdown:
            _logger.debug(f"Memory usage (RSS): {this_proc.memory_info().rss / 1024 / 1024:.2f} MB")
            _logger.debug(f"Memory usage (VMS): {this_proc.memory_info().vms / 1024 / 1024:.2f} MB")

            # Listen for commands/events from the coordinator
            timeout_millis = self._config.refining.flow_collection_frequency_millis
            self._coordinator_interface.listen_with_timeout(self, timeout_millis)

            if self._shutdown:
                break

            # Handle the flows that have can be collected since the last iteration
            ready_flows = self._collect_and_classify_flows('ready')
            ongoing_flows = self._collect_and_classify_flows('ongoing')
            if len(ready_flows[0]) + len(ongoing_flows[0]) == 0:
                continue  # No flows were collected

            # Register flow stats
            self._stats.register_flows(ready_flows[0], ready_flows[2], ready_flows[3])
            self._stats.register_ongoing_flow_count(len(ongoing_flows[0]))

            # Filter out the flows that should be monitored (the rest should be logged, but nothing more)
            monitored_mask = self._calculate_monitored_flow_indexes(ready_flows[0])
            ready_flows = tuple(np.array(x)[monitored_mask] for x in ready_flows)
            self._stats.register_monitored_flow_count(len(ready_flows[0]))
            monitored_mask = self._calculate_monitored_flow_indexes(ongoing_flows[0])
            ongoing_flows = tuple(np.array(x)[monitored_mask] for x in ongoing_flows)

            # Store the flows
            self._recent_flows.add_new_flows(*ready_flows)
            if not self._config.export_monitoring_data:  # We mustn't forget data if we're exporting it
                self._recent_flows.forget_old_flows()
            self._recent_flows.set_ongoing_flows(*ongoing_flows)

            # Get the flows (which includes both the ready and the ongoing flows)
            scoring_flows = self._recent_flows.get_flows_last_n_sec(self._config.refining.scoring_flow_time_window_sec)
            train_flows = self._recent_flows.get_flows_last_n_sec(self._config.refining.training_flow_time_window_sec)

            # Don't try to evaluate/improve the model if we don't have enough data yet
            if scoring_flows is None or train_flows is None:
                _logger.info(f"Recent flow count ({self._recent_flows.count()}) too low, skipping model evaluation")
                continue

            scoring_flow_data, scoring_flow_features, scoring_flow_pred, scoring_flow_true_labels = scoring_flows
            train_flow_data, train_flow_features, _, train_flow_true_labels = train_flows

            # Record both the estimated and the actual score: if they differ, we might need to fix some bugs
            current_score_estimate = self._refiner.get_estimated_model_score(self._model, scoring_flow_data,
                                                                             scoring_flow_features,
                                                                             scoring_flow_true_labels)
            self._stats.register_time_window_score('current_estimate', current_score_estimate)
            current_score_actual = self._refiner.get_actual_model_score(scoring_flow_pred, scoring_flow_true_labels)
            self._stats.register_time_window_score('current_actual', current_score_actual)

            # Determine whether model refinement is necessary
            # Reasons to use the estimated score:
            # - The estimated score tells us how the past flows would be classified by the model,
            #   meaning that the current model's performance is immediately available
            # - The actual score only changes after new flows are classified, which might take a while
            current_score = current_score_estimate
            if not self._refiner.is_model_refinement_necessary(current_score):
                continue

            # Create a refined model
            new_model = self._refiner.refine_model(train_flow_data, train_flow_features, train_flow_true_labels)
            new_score = self._refiner.get_estimated_model_score(new_model, scoring_flow_data, scoring_flow_features,
                                                                scoring_flow_true_labels)
            self._stats.register_time_window_score('new_estimate', new_score)
            new_acceptable = self._refiner.is_new_model_acceptable(current_score, new_score)
            self._refiner.visualize_model(new_model, new_score, train_flow_true_labels, new_acceptable)
            if not new_acceptable:
                continue

            if self._shutdown:
                break

            # Send the refined model to the coordinator
            self._coordinator_interface.send_refined_model(new_model)

        self._oracle_interface.close()
        self._coordinator_interface.close()

    def _collect_and_classify_flows(self, collect_what: Literal['ready', 'ongoing']) -> Tuple[ListOfFlowDataSchema,
    ListOfFeaturesSchema, ListOfFlowPredSchema, ListOfLabelSchema]:  # noqa
        """
        Collects the flows that can be collected or have reached the maximum packet count,
        classifies them, and returns the results. Flows which couldn't be classified are not returned.
        """
        # Collect the new flows
        _logger.debug(f"Collecting {collect_what} flows...")
        collected = self._monitoring_api.collect_ready_flows() if collect_what == 'ready' \
            else self._monitoring_api.collect_ongoing_flows()
        new_flow_data, new_flow_features, new_flow_pred = collected
        if len(new_flow_data) == 0:
            _logger.debug("No flows were collected")
            return new_flow_data, new_flow_features, new_flow_pred, np.zeros((0,), dtype=np.uint32)

        # Classify the collected flows
        _logger.info("Requesting classification for the flows...")
        # We could add a cache here because ongoing flows are sent multiple times, but it might not be the best idea:
        #   the true label of ongoing flows might change as more data becomes available
        new_flow_true_labels = self._oracle_interface.request_classification(new_flow_data, new_flow_features)
        count_original_new = len(new_flow_data)

        # Filter out the flows that were not classified: we can't really use them for anything
        #   (ideally, there aren't any, but we still need to handle this case)
        classified_mask = new_flow_true_labels != Label.NOT_SET
        new_flow_data, new_flow_features = new_flow_data[classified_mask], new_flow_features[classified_mask]
        new_flow_pred, new_flow_true_labels = new_flow_pred[classified_mask], new_flow_true_labels[classified_mask]

        _logger.info(f"{len(new_flow_data)} {collect_what} flows were collected and classified"
                     f" (+{count_original_new - len(new_flow_data)} couldn't be classified)")

        return new_flow_data, new_flow_features, new_flow_pred, new_flow_true_labels

    def _calculate_monitored_flow_indexes(self, flow_data: ListOfFlowDataSchema) -> np.ndarray:
        """
        Calculates the indexes of the flows that should be uses for training.
        It is possible that all flows are collected to be included in the statistics, but only a subset of them
        should be used for training (monitoring). This method selects this subset.
        """
        if not self._config.stats_from_all_flows:
            # Only the flows that should be monitored got collected, so no filtering is necessary
            return np.ones((len(flow_data),), dtype=bool)
        elif self._config.monitored_flow_ratio <= 0:
            # No flows should be monitored, so return an empty mask
            return np.zeros((len(flow_data),), dtype=bool)
        else:
            # Calculate the hash of the flow ID and use it to select a subset of flows
            flow_id_hash = np.sum(flow_data[:, range(FlowDataCols.flow_id_begin(), FlowDataCols.flow_id_end() + 1)],
                                  axis=1, dtype=np.uint32) * 37
            mod_value = 10_000
            return flow_id_hash % mod_value <= round(mod_value * self._config.monitored_flow_ratio)
