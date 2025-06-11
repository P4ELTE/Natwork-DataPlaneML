import logging
from typing import Optional

import numpy as np
from sklearn.metrics import accuracy_score, f1_score

from lib_common.flow import Label

_logger = logging.getLogger(__name__)

if len(Label.excluding_not_set()) != 2:
    # F1 score is primarily designed for binary classification
    _logger.error("More than 2 labels found; classification score calculation might not work as expected")


def calculate_accuracy_not_set_is_benign(y_true: np.ndarray, y_pred: np.ndarray, weight: np.ndarray = None) -> float:
    """
    Calculates the accuracy from the given true and predicted labels.
    Flows without a label are treated as benign.
    """

    if len(y_true) == 0:
        raise RuntimeError("Unable to calculate score: no flows to evaluate")

    # Treat not set predicted label as benign label, without modifying the original array
    y_pred = np.where(y_pred == Label.NOT_SET, Label.BENIGN, y_pred)

    return accuracy_score(y_true, y_pred, sample_weight=weight)


def calculate_f1_score_not_set_is_benign(y_true: np.ndarray, y_pred: np.ndarray,
                                         score_if_only_benign: Optional[float] = None,
                                         weight: np.ndarray = None) -> float:
    """
    Calculates the F1 score from the given true and predicted labels.
    Flows without a label are treated as benign.
    """

    if len(y_true) == 0:
        raise RuntimeError("Unable to calculate score: no flows to evaluate")

    # Treat not set predicted label as benign label, without modifying the original array
    y_pred = np.where(y_pred == Label.NOT_SET, Label.BENIGN, y_pred)

    return _calculate_f1_score_raw(y_true, y_pred, score_if_only_benign, weight)


def calculate_f1_score_excluding_not_set(y_true: np.ndarray, y_pred: np.ndarray,
                                         score_if_only_not_set: float,
                                         score_if_only_benign: Optional[float] = None,
                                         weight: np.ndarray = None) -> float:
    """
    Calculates the F1 score from the given true and predicted labels.
    Flows without a label are excluded from the calculation: they are treated as if they were not present.
    """

    # Exclude flows without a label, without modifying the original arrays
    y_true = y_true[y_pred != Label.NOT_SET]
    y_pred = y_pred[y_pred != Label.NOT_SET]

    if len(y_true) == 0:
        return score_if_only_not_set

    return _calculate_f1_score_raw(y_true, y_pred, score_if_only_benign, weight)


def _calculate_f1_score_raw(y_true: np.ndarray, y_pred: np.ndarray, score_if_only_benign: Optional[float],
                            weight: np.ndarray) -> float:
    """Calculates the F1 score from the given true and predicted labels."""

    # Use F1 score if there is at least one attack flow.
    # Otherwise, use mean accuracy instead: F1 score doesn't work well in that case.

    if np.any(y_true == Label.ATTACK):
        return f1_score(y_true, y_pred, pos_label=Label.ATTACK, sample_weight=weight)
    elif score_if_only_benign is None:
        return accuracy_score(y_true, y_pred, sample_weight=weight)
    else:
        return score_if_only_benign
