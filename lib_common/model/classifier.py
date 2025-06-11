from typing import Optional

import numpy as np

from lib_common.flow import ListOfFlowDataSchema, ListOfFeaturesSchema, ListOfFlowPredSchema, \
    FlowDataCols, Label, FlowPredCols
from lib_common.model.data import Model, ModelRF


def calculate_classifiable_flows_mask(flow_data: ListOfFlowDataSchema,
                                      predictions: ListOfFlowPredSchema,
                                      flow_length: int) -> np.ndarray:
    """
    Returns a boolean mask indicating which flows are eligible for classification:
    - flows that have not been classified yet
    - flows that are long enough to be classified at the given length
    """
    # noinspection PyTypeChecker
    mask = predictions[:, FlowPredCols.PREDICTED_LABEL] == Label.NOT_SET  # Unclassified flows
    mask &= flow_data[:, FlowDataCols.TOTAL_COUNT] >= flow_length  # Long enough flows
    # noinspection PyTypeChecker
    return mask


def classify_flows_with_model(certainty_threshold: float, model: Model, flow_data: ListOfFlowDataSchema,
                              flow_features: ListOfFeaturesSchema) -> ListOfFlowPredSchema:
    """
    Attempts to classify each flow just like the data plane, returning the assigned labels in a separate array.
    Some flows may fail to be classified, in which case they receive the "not set" label.
    "ASAP" classification is used, meaning that flows are attempted to be classified as early as possible:
    if a classification is possible with only the first N packets, that classification is accepted.
    """

    # Initialize the result array with the "not set" label
    predictions = np.zeros((len(flow_data), len(FlowPredCols)), dtype=np.uint32)

    # Progressively classify all flows at once with increasing flow length
    #   (instead of classifying each flow individually)
    max_flow_length = max(model.flow_length_to_id.keys()) if len(model.flow_length_to_id) > 0 else 0
    for flow_length in range(1, max_flow_length + 1):
        # Determine which RF to use
        if not (rf := model.id_to_rf.get(model.flow_length_to_id.get(flow_length, None), None)):
            continue

        # Early return if no flows are eligible for classification: if at some point no flows are eligible,
        #  then no further classification is possible even at higher flow lengths
        classifiable_mask = calculate_classifiable_flows_mask(flow_data, predictions, flow_length)
        if not classifiable_mask.any():
            break

        # Classify the flows with the current RF
        classify_flows_with_rf(certainty_threshold, flow_length, rf, flow_data,
                               flow_features, predictions, classifiable_mask)

    return predictions


def classify_flows_with_rf(certainty_threshold: float, flow_length: int, rf: ModelRF,
                           flow_data: ListOfFlowDataSchema, flow_features: ListOfFeaturesSchema,
                           result: ListOfFlowPredSchema, classifiable_mask: Optional[np.ndarray] = None) -> None:
    """
    Classifies the given flows using a specific RF at a specific flow length, instead of using an entire model over
    multiple flow lengths. The classification results are saved in the array given as a parameter.
    Some flows may fail to be classified, in which case they receive the "not set" label.

    Optionally a mask can be provided to indicate which flows are eligible for classification.
    If not provided, the mask is calculated automatically.
    """

    # Determine which flows are eligible for classification: unclassified flows that have reached the current length
    if classifiable_mask is None:
        classifiable_mask = calculate_classifiable_flows_mask(flow_data, result, flow_length)

    # Classify the eligible flows
    certainties = rf.classifier.predict_proba(flow_features[classifiable_mask, flow_length - 1])
    accepted_mask = np.max(certainties, axis=1) >= certainty_threshold
    accepted_labels = rf.classifier.classes_[np.argmax(certainties[accepted_mask], axis=1)]

    # Save the classification results
    indices = np.nonzero(classifiable_mask)[0]
    result[indices[accepted_mask], FlowPredCols.PREDICTED_LABEL] = accepted_labels
    result[indices[accepted_mask], FlowPredCols.PREDICTED_AT_COUNT] = flow_length
