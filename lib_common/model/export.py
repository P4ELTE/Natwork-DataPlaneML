import concurrent.futures
import logging
import multiprocessing.context
from concurrent.futures import Future
from pathlib import Path
from typing import List

from matplotlib import pyplot as plt
from matplotlib.axes import Axes
from matplotlib.backends.backend_pdf import PdfPages
from matplotlib.figure import Figure
from sklearn.tree import plot_tree, DecisionTreeClassifier

from lib_common.flow import Feature, Label
from lib_common.model.data import Model, ModelRF

_logger = logging.getLogger(__name__)
_executor = concurrent.futures.ProcessPoolExecutor(max_workers=1, mp_context=multiprocessing.context.SpawnContext())


def visualize_model_nonblocking(model: Model, identifier: str, save_path: Path, first_page: str = "") -> None:
    """
    Calls visualize_model in a separate thread or process. Does not wait for it to complete.
    This method was created because visualization can take multiple seconds.
    """

    def done_callback(f: Future) -> None:
        if f.exception() is None:
            _logger.debug(f"Visualization of model '{identifier}' completed successfully.")
        else:
            _logger.error(f"Visualization of model '{identifier}' failed:")
            _logger.error(f.exception())

    _logger.debug(f"Exporting visualization of model '{identifier}' to {save_path}")
    _executor.submit(visualize_model, model, identifier, save_path, first_page).add_done_callback(done_callback)


def visualize_model(model: Model, identifier: str, save_path: Path, first_page: str = "") -> None:
    """Visualizes a model, saving the graphics into the given directory."""
    _logger.debug(f"Exporting visualization of model '{identifier}' to {save_path}")
    save_path.parent.mkdir(parents=True, exist_ok=True)
    with PdfPages(save_path) as pages:
        if len(first_page) > 0:
            fig = plt.figure(figsize=(20, 10))
            fig.text(0.05, 0.95, first_page, fontsize=12, ha='left', va='top')
            pages.savefig(fig)
            plt.close(fig)

        for rf_id, rf in model.id_to_rf.items():
            flow_lengths = [length for length, other_rf_id in model.flow_length_to_id.items() if other_rf_id == rf_id]
            _visualize_rf(pages, rf_id, rf, flow_lengths)


def _visualize_rf(pages: PdfPages, rf_id: int, rf: ModelRF, flow_lengths: List[int]) -> None:
    """Visualizes a single random forest, saving the figures to the given PDF pages."""
    # General information about RF
    fig = plt.figure(figsize=(20, 10))
    text = f"""
    RF ID: {rf_id}
    Trained on flow length of: {rf.trained_on_flow_length}
    Used on flow lengths of: {', '.join(map(str, flow_lengths))}
    """
    fig.text(0.5, 0.5, text, fontsize=12, ha='center', va='center')
    pages.savefig(fig)
    plt.close(fig)

    # Decision Trees
    for index, dt in enumerate(rf.dts):
        dt_fig = _visualize_dt(index, dt)
        pages.savefig(dt_fig)
        plt.close(dt_fig)


def _visualize_dt(index: int, dt: DecisionTreeClassifier) -> Figure:
    """Visualizes a single decision tree, returning the created figure."""
    fig: Figure = plt.figure(figsize=(20, 10))
    fig.suptitle(f"Decision Tree #{index}")
    ax: Axes = fig.add_subplot()
    plot_tree(dt, ax=ax, feature_names=[f.name for f in Feature],
              class_names=[label.name for label in Label.excluding_not_set()],
              filled=True, node_ids=False, proportion=True, impurity=False, precision=2)
    return fig
