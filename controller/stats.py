import abc
import dataclasses
import enum
import logging
import math
import pickle
import queue
import threading
import time
from pathlib import Path
from typing import Callable, List, Literal, Tuple

import numpy as np
import sklearn
from matplotlib import pyplot as plt
from matplotlib.axes import Axes
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.figure import Figure

from controller.data import ControllerConfig
from lib_common.flow import FlowDataCols, FlowPredCols, Label, ListOfFlowDataSchema, ListOfFlowPredSchema, \
    ListOfLabelSchema
from lib_common.model.data import Model
from lib_common.model.score import calculate_accuracy_not_set_is_benign, calculate_f1_score_not_set_is_benign

_logger = logging.getLogger(__name__)


class _FlowStatsCols(enum.IntEnum):
    """
    The columns of the flow stats matrix. See different enums for what each column represents:
    FlowDataCols, FlowPredCols
    """
    SWITCH_ORDINAL = 0
    TOTAL_COUNT = enum.auto()
    FIRST_SEEN_MS = enum.auto()
    LAST_SEEN_MS = enum.auto()
    PREDICTED_LABEL = enum.auto()
    PREDICTED_AT_COUNT = enum.auto()
    TRUE_LABEL = enum.auto()


@dataclasses.dataclass(frozen=True)
class _ModelDeploymentData:
    """Container of saved data regarding model deployments."""
    start_time_ms: int  # When the deployment started
    duration_ms: int  # How long deployment took
    model_complexity: int  # Sum of the complexities of the models deployed


class StatsManager(abc.ABC):
    """
    Class responsible for storing and visualizing statistics regarding how a controller instance functions.
    The collected statistics can be plotted directly or exported in raw form for further processing.
    """

    def __init__(self, start_time_ms: int, config: ControllerConfig) -> None:
        self._start_time_ms = start_time_ms
        self._config = config

    @abc.abstractmethod
    def finished(self) -> None:
        """Should be called when the data collection is finished."""
        pass

    @abc.abstractmethod
    def register_flows(self, flow_data: ListOfFlowDataSchema, flow_pred: ListOfFlowPredSchema,
                       flow_true_label: ListOfLabelSchema) -> None:
        """Stores the flows and the in-network prediction results."""
        pass

    @abc.abstractmethod
    def register_ongoing_flow_count(self, count: int) -> None:
        """Stores the timestamp and the number of ongoing flows."""
        pass

    @abc.abstractmethod
    def register_monitored_flow_count(self, count: int) -> None:
        """
        Stores how many new flows are treated as monitored flows.
        The ultimate goal is to validate that the ratio of monitored and total flows is as expected.
        """
        pass

    @abc.abstractmethod
    def register_time_window_score(self, what: Literal['current_actual', 'current_estimate', 'new_estimate'],
                                   f1_score: float) -> None:
        """
        Stores the timestamp and the F1 score of a model, calculated based on the most recent flows.
        """
        pass

    @abc.abstractmethod
    def register_model_deployment(self, deployment_duration_ms: int, model: Model) -> None:
        """Stores the timestamp and delta-time of new model deployments."""
        pass

    @abc.abstractmethod
    def export(self, save_path: Path) -> None:
        """Saves the collected data to a file, allowing for further processing and e.g. merging with other sources."""
        pass

    @abc.abstractmethod
    def visualize(self, save_figure_dir: Path, save_figure_prefix: str) -> None:
        """Plots the statistics, saving the figure(s) as PDFs."""
        pass


class StatsManagerContainer(StatsManager):
    """Contains multiple StatsManager instances and delegates calls to them."""

    def __init__(self, managers: List[StatsManager]) -> None:
        super().__init__(managers[0]._start_time_ms, managers[0]._config)
        self._instances: List[StatsManager] = list(managers)

    def finished(self) -> None:
        for e in self._instances:
            e.finished()

    def register_flows(self, flow_data: ListOfFlowDataSchema, flow_pred: ListOfFlowPredSchema,
                       flow_true_label: ListOfLabelSchema) -> None:
        for e in self._instances:
            e.register_flows(flow_data, flow_pred, flow_true_label)

    def register_ongoing_flow_count(self, count: int) -> None:
        for e in self._instances:
            e.register_ongoing_flow_count(count)

    def register_monitored_flow_count(self, count: int) -> None:
        for e in self._instances:
            e.register_monitored_flow_count(count)

    def register_time_window_score(self, what: Literal['current_actual', 'current_estimate', 'new_estimate'],
                                   f1_score: float) -> None:
        for e in self._instances:
            e.register_time_window_score(what, f1_score)

    def register_model_deployment(self, deployment_duration_ms: int, model: Model) -> None:
        for e in self._instances:
            e.register_model_deployment(deployment_duration_ms, model)

    def export(self, save_path: Path) -> None:
        for e in self._instances:
            e.export(save_path)

    def visualize(self, save_figure_dir: Path, save_figure_prefix: str) -> None:
        for e in self._instances:
            e.visualize(save_figure_dir, save_figure_prefix)


class Influxdb3StatsManager(StatsManager):
    """
    Stats manager implementation that pushes data to an InfluxDB 3 instance.
    A background thread is used when writing data, but it is not strictly necessary when batched writing is used:
    the batched mode is already asynchronous and does not block the main thread.
    """

    from influxdb_client_3 import Point

    def __init__(self, start_time_ms: int, config: ControllerConfig, controller_id: str) -> None:
        super().__init__(start_time_ms, config)
        self._controller_id: str = controller_id
        self._flow_row_id = 0

        self._queue: queue.Queue = queue.Queue()
        self._io_thread = threading.Thread(target=Influxdb3StatsManager._io_thread,
                                           args=(config.stats_db.hostname, config.stats_db.database_name,
                                                 config.stats_db.auth_token, self._queue))
        self._io_thread.start()

    @staticmethod
    def _io_thread(host: str, database: str, token: str, point_queue: queue.Queue) -> None:
        """Entry point of the thread responsible for writing data to InfluxDB 3."""
        from influxdb_client_3 import InfluxDBClient3, WriteOptions, write_client_options
        write_options = WriteOptions(flush_interval=1_000, retry_interval=500)  # batched writes, flushed every second
        wco = write_client_options(write_options=write_options)
        client = InfluxDBClient3(host=host, database=database, token=token, write_client_options=wco)

        _logger.info("InfluxDB 3 stats manager started")
        while (item := point_queue.get()) is not None:
            client.write(item)
        _logger.info("Received poison pill, stopping InfluxDB 3 client")
        client.close()
        _logger.debug("InfluxDB 3 IO thread returning...")

    def _write(self, measurement: str, point_filler: Callable[[Point], Point]) -> None:
        from influxdb_client_3 import Point
        point = Point(measurement).tag("controller", self._controller_id).time(time.time_ns())
        point = point_filler(point)
        self._queue.put(point)

    def finished(self) -> None:
        self._queue.put(None)
        _logger.info("Waiting for InfluxDB 3 IO thread to finish")
        self._io_thread.join()
        _logger.debug("InfluxDB 3 IO thread has finished")

    def register_flows(self, flow_data: ListOfFlowDataSchema, flow_pred: ListOfFlowPredSchema,
                       flow_true_label: ListOfLabelSchema) -> None:
        from influxdb_client_3 import Point
        points = [
            Point('flow').tag("controller", self._controller_id).tag("row_id", str(self._flow_row_id + i))
            .field('switch', flow_data[i][FlowDataCols.SWITCH_ORDINAL])
            .field('total_count', flow_data[i][FlowDataCols.TOTAL_COUNT])
            .time((flow_data[i][FlowDataCols.FIRST_SEEN_MS] + self._start_time_ms) * 1_000_000)
            .field('end_time', (flow_data[i][FlowDataCols.LAST_SEEN_MS] + self._start_time_ms) * 1_000_000)
            .field('predicted_label', flow_pred[i][FlowPredCols.PREDICTED_LABEL])
            .field('predicted_at_count', flow_pred[i][FlowPredCols.PREDICTED_AT_COUNT])
            .field('true_label', flow_true_label[i])
            for i in range(len(flow_data))
        ]
        self._flow_row_id += len(flow_data)
        self._queue.put(points)

    def register_ongoing_flow_count(self, count: int) -> None:
        self._write('ongoing_flow_count', lambda p: p.field("count", count))

    def register_monitored_flow_count(self, count: int) -> None:
        self._write('monitored_flow_count', lambda p: p.field("count", count))

    def register_time_window_score(self, what: Literal['current_actual', 'current_estimate', 'new_estimate'],
                                   f1_score: float) -> None:
        self._write('time_window_score', lambda p: p.field("type", what).field("f1_score", f1_score))

    def register_model_deployment(self, deployment_duration_ms: int, model: Model) -> None:
        end_time = time.time_ns()
        duration = deployment_duration_ms * 1_000_000
        self._write('model_deployment', lambda p: p
                    .time(end_time - duration)
                    .field("end_time", end_time)
                    .field("duration", duration)
                    .field("complexity", model.complexity))

    def export(self, save_path: Path) -> None:
        pass  # noop

    def visualize(self, save_figure_dir: Path, save_figure_prefix: str) -> None:
        pass  # noop


class MatplotlibStatsManager(StatsManager):
    """Stats manager implementation that stores data in memory and visualizes using Matplotlib."""

    def __init__(self, start_time_ms: int, config: ControllerConfig) -> None:
        super().__init__(start_time_ms, config)

        self._flow_stats = np.ndarray((1024, len(_FlowStatsCols)), dtype=np.uint32)
        self._total_flow_count: int = 0
        self._monitored_flow_count: int = 0

        # Cols: timestamp, score, current/new
        self._time_window_score: np.ndarray = np.zeros((0, 3), dtype=np.uint32)

        self._ongoing_flow_count: List[Tuple[int, int]] = []  # (timestamp, count)
        self._new_model_deployed: List[_ModelDeploymentData] = []
        self._last_time_ms: int = -1

    def finished(self) -> None:
        self._last_time_ms = time.time_ns() // 1_000_000 - self._start_time_ms

    def register_flows(self, flow_data: ListOfFlowDataSchema, flow_pred: ListOfFlowPredSchema,
                       flow_true_label: ListOfLabelSchema) -> None:
        # Resize the array if the new data does not fit
        while len(self._flow_stats) - self._total_flow_count < len(flow_data):
            self._flow_stats.resize(len(self._flow_stats) * 2, len(_FlowStatsCols))

        # Store the data
        i, j = self._total_flow_count, self._total_flow_count + len(flow_data)
        self._total_flow_count += len(flow_data)
        self._flow_stats[i:j, _FlowStatsCols.SWITCH_ORDINAL] = flow_data[:, FlowDataCols.SWITCH_ORDINAL]
        self._flow_stats[i:j, _FlowStatsCols.TOTAL_COUNT] = flow_data[:, FlowDataCols.TOTAL_COUNT]
        self._flow_stats[i:j, _FlowStatsCols.FIRST_SEEN_MS] = flow_data[:, FlowDataCols.FIRST_SEEN_MS]
        self._flow_stats[i:j, _FlowStatsCols.LAST_SEEN_MS] = flow_data[:, FlowDataCols.LAST_SEEN_MS]
        self._flow_stats[i:j, _FlowStatsCols.PREDICTED_LABEL] = flow_pred[:, FlowPredCols.PREDICTED_LABEL]
        self._flow_stats[i:j, _FlowStatsCols.PREDICTED_AT_COUNT] = flow_pred[:, FlowPredCols.PREDICTED_AT_COUNT]
        self._flow_stats[i:j, _FlowStatsCols.TRUE_LABEL] = flow_true_label

    def register_ongoing_flow_count(self, count: int) -> None:
        self._ongoing_flow_count.append((time.time_ns() // 1_000_000 - self._start_time_ms, count))

    def register_monitored_flow_count(self, count: int) -> None:
        self._monitored_flow_count += count

    def register_time_window_score(self, what: Literal['current_actual', 'current_estimate', 'new_estimate'],
                                   f1_score: float) -> None:
        what_num = {'current_actual': 0, 'current_estimate': 1, 'new_estimate': 2}[what]
        new_row = [time.time_ns() // 1_000_000 - self._start_time_ms, f1_score, what_num]
        self._time_window_score = np.vstack((self._time_window_score, new_row))

    def register_model_deployment(self, deployment_duration_ms: int, model: Model) -> None:
        self._new_model_deployed.append(_ModelDeploymentData(
                start_time_ms=time.time_ns() // 1_000_000 - self._start_time_ms - deployment_duration_ms,
                duration_ms=deployment_duration_ms,
                model_complexity=model.complexity
        ))

    def export(self, save_path: Path) -> None:
        # Serialize the data, so that we don't have to import anything when loading it
        def serialize(x) -> dict:
            import json
            return json.loads(json.dumps(x, default=lambda y: vars(y) if dataclasses.is_dataclass(y) else str(y)))

        data = {
            # Prefix with '_': in case we copy-paste code, it should still work
            '_start_time_ms': self._start_time_ms,
            '_config': serialize(self._config),
            '_flow_stats': self._flow_stats[:self._total_flow_count],
            '_total_flow_count': self._total_flow_count,
            '_time_window_score': self._time_window_score,
            '_ongoing_flow_count': self._ongoing_flow_count,
            '_new_model_deployed': serialize(self._new_model_deployed),
            '_last_time_ms': self._last_time_ms,
        }
        save_path.parent.mkdir(parents=True, exist_ok=True)
        with save_path.open('wb') as f:
            # noinspection PyTypeChecker
            pickle.dump(data, f)

    def visualize(self, save_figure_dir: Path, save_figure_prefix: str) -> None:
        if self._total_flow_count == 0:
            _logger.error("No data to visualize, skipping")
            return

        figures = [
            self._visualize_plot_time(save_figure_dir / f'{save_figure_prefix}_time.pdf'),
            self._visualize_basic_data(save_figure_dir / f'{save_figure_prefix}_basic.pdf'),
            self._visualize_model_deployments(save_figure_dir / f'{save_figure_prefix}_deployments.pdf'),
            self._visualize_confusion_matrix(save_figure_dir / f'{save_figure_prefix}_confusion_matrix.pdf'),
        ]

        with PdfPages(str(save_figure_dir / f"{save_figure_prefix}_MERGED.pdf")) as pages:
            for fig in figures:
                pages.savefig(fig)
                plt.close(fig)

    def _visualize_plot_time(self, save_figure_path: Path, chunk_length_ms: int = 10_000) -> Figure:
        """Visualizes the data which requires a time axis."""
        fig, count_ax = plt.subplots(figsize=(8, 5))
        fig: Figure = fig
        count_ax.set_xlabel('Time (sec)')

        count_ax: Axes = count_ax
        count_ax.set_ylabel('Flow count')
        count_ax.set_xlim(0, self._last_time_ms / 1_000)
        score_ax: Axes = count_ax.twinx()
        score_ax.set_ylabel('F1 score')
        score_ax.set_ylim(-0.02, 1.02)

        self._plot_time_vs_flows(count_ax, score_ax, chunk_length_ms)
        self._plot_time_vs_model_scores(score_ax)
        self._plot_time_related_other(count_ax, score_ax)

        # Display count axis on top
        count_ax.set_zorder(1)
        count_ax.set_frame_on(False)

        # Place the legend at the top of the figure
        fig.legend(loc='upper center', ncol=2)
        count_ax.set_position([0.1, 0.1, 0.8, 0.65])

        fig.savefig(str(save_figure_path))
        return fig

    def _plot_time_vs_flows(self, count_ax: Axes, score_ax: Axes, chunk_length_ms: int) -> None:
        """
        Plots the number of flows and their F1 score over time. The time is divided into chunks of chunk_length_ms.
        """

        start_timestamps = self._flow_stats[:self._total_flow_count, _FlowStatsCols.FIRST_SEEN_MS]
        stop_timestamps = self._flow_stats[:self._total_flow_count, _FlowStatsCols.LAST_SEEN_MS]
        y_true = self._flow_stats[:self._total_flow_count, _FlowStatsCols.TRUE_LABEL]
        y_pred = self._flow_stats[:self._total_flow_count, _FlowStatsCols.PREDICTED_LABEL]

        if len(start_timestamps) == 0:
            _logger.warning("No flow data to plot")
            return

        # Create chunks
        time_min = min(start_timestamps.min(), stop_timestamps.min())
        time_max = max(start_timestamps.max(), stop_timestamps.max())
        chunk_edges = np.arange(time_min, time_max + chunk_length_ms + 1, chunk_length_ms)

        # Calculate the X axis values
        x = chunk_edges[1:] / 1_000  # Take the end of the chunks and convert to seconds

        # Started flows
        # indices_start = np.digitize(start_timestamps, chunk_edges) - 1
        # y_start = np.bincount(indices_start, minlength=len(x)) / (chunk_length_ms / 1_000)
        # count_ax.plot(x, y_start, color='cyan', linestyle='dotted', zorder=30,
        #               label=f'Started Flows / sec (last {round(chunk_length_ms / 1_000)} sec avg)')

        # Stopped flows
        indices_stop = np.digitize(stop_timestamps, chunk_edges) - 1
        y_stop = np.bincount(indices_stop, minlength=len(x)) / (chunk_length_ms / 1_000)
        # count_ax.plot(x, y_stop, color='pink', linestyle='dotted', zorder=31,
        #               label=f'Stopped Flows / sec (last {round(chunk_length_ms / 1_000)} sec avg)')

        # Started flows per label
        label_colors = ['cyan', 'pink']
        for label in Label.excluding_not_set():
            label_color = label_colors[label % len(label_colors)]  # In case more labels get added later
            label_name = label.name.capitalize()
            timestamps_label = start_timestamps[y_true == label]
            indices_label = np.digitize(timestamps_label, chunk_edges) - 1
            y_label = np.bincount(indices_label, minlength=len(x)) / (chunk_length_ms / 1_000)
            count_ax.plot(x, y_label, color=label_color, linestyle='dotted', zorder=30,
                          label=f'Started {label_name} Flows / sec (last {round(chunk_length_ms / 1_000)} sec avg)')

        # F1 score
        y_score = np.asarray([
            math.nan if count == 0 else calculate_f1_score_not_set_is_benign(y_true[indices_stop == i],
                                                                             y_pred[indices_stop == i],
                                                                             score_if_only_benign=math.nan)
            for i, count in enumerate(y_stop)
        ])
        # Don't plot the NaN values: make the line continuous
        score_ax.plot(x[~np.isnan(y_score)], y_score[~np.isnan(y_score)], color='blue', linestyle='solid', zorder=18,
                      label=f'Actual F1 Score (last {round(chunk_length_ms / 1_000)} sec)')

    def _plot_time_vs_model_scores(self, score_ax: Axes) -> None:
        """Plots model score related plots."""
        if len(self._time_window_score) == 0:
            _logger.warning("No model scores to plot")
            return

        last_n_sec = f"(last {self._config.refining.scoring_flow_time_window_sec} sec)"
        current_model_actual_score = self._time_window_score[self._time_window_score[:, 2] == 0]
        score_ax.plot(current_model_actual_score[:, 0] / 1_000, current_model_actual_score[:, 1],
                      color='navy', linestyle='solid', zorder=19,
                      label=f'Current Model Actual Score {last_n_sec}')

        current_model_estimated_score = self._time_window_score[self._time_window_score[:, 2] == 1]
        score_ax.plot(current_model_estimated_score[:, 0] / 1_000, current_model_estimated_score[:, 1],
                      color='yellow', linestyle='dashed', zorder=20,
                      label=f'Current Model Estimated Score {last_n_sec}')

        new_model_score = self._time_window_score[self._time_window_score[:, 2] == 2]
        score_ax.plot(new_model_score[:, 0] / 1_000, new_model_score[:, 1],
                      color='orange', linestyle='dotted', zorder=21,
                      label=f'New Model Estimated Score {last_n_sec}')

    def _plot_time_related_other(self, count_ax: Axes, score_ax: Axes) -> None:
        """Plots line plots."""
        # Target F1 score
        score_ax.axhline(self._config.refining.target_latest_flow_f1_score, color='red',
                         linestyle='solid', linewidth=1, zorder=11, label='Target F1 Score')

        # Overall F1 score
        y_true = self._flow_stats[:self._total_flow_count, _FlowStatsCols.TRUE_LABEL]
        y_pred = self._flow_stats[:self._total_flow_count, _FlowStatsCols.PREDICTED_LABEL]
        overall_f1_score = calculate_f1_score_not_set_is_benign(y_true, y_pred)
        score_ax.axhline(overall_f1_score, color='red', linestyle=(0, (5, 10)), linewidth=1, zorder=12,
                         label='Overall Actual F1 Score')

        # Ongoing flow count
        # count_ax.plot([time_ms / 1_000 for time_ms, count in self._ongoing_flow_count],
        #               [count for time_ms, count in self._ongoing_flow_count],
        #               color='grey', linestyle='solid', zorder=13,
        #               label='Ongoing Flow Count')

        # New model deployment
        for i, deployment in enumerate(self._new_model_deployed):
            score_ax.axvline(deployment.start_time_ms / 1_000, color='black', linestyle='solid', zorder=10,
                             label='New Model Deployed' if i == 0 else None)  # Only add a single legend entry

    def _visualize_basic_data(self, save_figure_path: Path) -> Figure:
        """Visualizes some basic data about the controller, its configuration, and the results."""
        fig, ax = plt.subplots(figsize=(8, 5))
        fig: Figure = fig
        ax: Axes = ax
        ax.set_axis_off()

        flow_packet_counts = self._flow_stats[:self._total_flow_count, _FlowStatsCols.TOTAL_COUNT]
        y_true = self._flow_stats[:self._total_flow_count, _FlowStatsCols.TRUE_LABEL]
        y_pred = self._flow_stats[:self._total_flow_count, _FlowStatsCols.PREDICTED_LABEL]
        f1_score = calculate_f1_score_not_set_is_benign(y_true, y_pred, -1)
        accuracy = calculate_accuracy_not_set_is_benign(y_true, y_pred)
        _logger.warning(f"Overall F1 score: {f1_score:.4f}, accuracy: {accuracy:.4f}")

        def quantiles(x: np.ndarray) -> str:
            if len(x) == 0:
                return "No data"
            x = np.sort(x)
            return f"{x[0]} - {x[len(x) // 4]} - {x[len(x) // 2]} - {x[3 * len(x) // 4]} - {x[-1]}"

        text = f"""
        Flow statistics:
        - Total flow count: {self._total_flow_count}
        - Monitored flow count: {self._monitored_flow_count} ({self._monitored_flow_count / self._total_flow_count * 100:.2f}%)
        - Target monitored flow ratio: {self._config.total_monitored_flow_ratio * 100:.2f}%
        - Packet count: min-Q1-median-Q3-max = {quantiles(flow_packet_counts)}
        
        Label statistics:
        - True: {Label.compute_count_statistics(self._flow_stats[:self._total_flow_count,
                                                _FlowStatsCols.TRUE_LABEL])}
        - Pred: {Label.compute_count_statistics(self._flow_stats[:self._total_flow_count,
                                                _FlowStatsCols.PREDICTED_LABEL])}
        
        Classification statistics:
        - Overall F1 score: {f1_score:.4f}
        - Overall accuracy: {accuracy:.4f}
        """
        fig.text(0.05, 0.95, text, fontsize=11, horizontalalignment='left', verticalalignment='top')

        fig.savefig(str(save_figure_path))
        return fig

    def _visualize_model_deployments(self, save_figure_path: Path) -> Figure:
        """Visualizes model deployments in detail, showing e.g. how long each deployment took."""
        fig, time_ax = plt.subplots(figsize=(8, 5))
        fig: Figure = fig

        time_ax: Axes = time_ax
        time_ax.set_xlabel('Time (sec)')
        time_ax.set_ylabel('Model Deployment Duration (ms)')
        time_ax.set_xlim(0, self._last_time_ms / 1_000)

        complexity_ax: Axes = time_ax.twinx()
        complexity_ax.set_ylabel('Model Complexity')

        # Vertical lines in the background
        # for i, deployment in enumerate(self._new_model_deployed):
        #     time_ax.axvline(deployment.time_ms / 1_000, color='black', linestyle='solid', zorder=10,
        #                     label='New Model Deployed' if i == 0 else None)  # Only add a single legend entry

        times = [deployment.start_time_ms / 1_000 for deployment in self._new_model_deployed]
        durations = [deployment.duration_ms for deployment in self._new_model_deployed]
        complexities = [deployment.model_complexity for deployment in self._new_model_deployed]

        # Plot lines
        time_ax.plot(times, durations, label='Deployment Duration', color='blue', linestyle='solid', zorder=20)
        complexity_ax.plot(times, complexities, label='Complexity', color='red', linestyle='dashed', zorder=21)

        # Color the background while a model is being deployed
        for i, deployment in enumerate(self._new_model_deployed):
            time_ax.axvspan(deployment.start_time_ms / 1_000,
                            (deployment.start_time_ms + deployment.duration_ms) / 1_000,
                            color='aqua', zorder=9,
                            label='Deployment in Progress' if i == 0 else None)  # Only add a single legend entry

        fig.legend(loc='upper center', ncol=2)
        time_ax.set_position([0.1, 0.1, 0.8, 0.75])

        fig.savefig(str(save_figure_path))
        return fig

    def _visualize_confusion_matrix(self, save_figure_path: Path) -> Figure:
        """Visualizes the confusion matrix: how many flows were classified correctly and incorrectly."""
        fig, (ax_raw, ax_normalized) = plt.subplots(1, 2, figsize=(8, 5))
        fig.suptitle("Confusion Matrix")
        ax_raw.set_title("Original counts")
        ax_normalized.set_title("Normalized")

        for (ax, normalize) in [(ax_raw, None), (ax_normalized, 'all')]:
            sklearn.metrics.ConfusionMatrixDisplay.from_predictions(
                    self._flow_stats[:self._total_flow_count, _FlowStatsCols.TRUE_LABEL],
                    self._flow_stats[:self._total_flow_count, _FlowStatsCols.PREDICTED_LABEL],
                    ax=ax,
                    labels=[x.value for x in Label],  # Necessary when not all labels are present in the data
                    display_labels=[x.name for x in Label],
                    cmap='Blues',
                    normalize=normalize,
                    colorbar=True
            )

        fig.tight_layout()
        fig.savefig(str(save_figure_path))
        return fig
