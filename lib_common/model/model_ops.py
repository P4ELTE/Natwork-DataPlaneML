from typing import Dict, Iterator, List, Set

from lib_common.model.data import Model, ModelRFSlice, ModelSlice


def remap_model_rf_ids(model: Model, new_ids: Iterator[int]) -> Model:
    """
    When switching to a new a model, some RF IDs might not be available for immediate use.
    This method allows remapping the model to only use free IDs.
    The returned model instance is a shallow copy of the original model.
    """
    old_to_new: Dict[int, int] = {old_id: next(new_ids) for old_id in model.id_to_rf.keys()}
    return Model(
            flow_length_to_id={length: old_to_new[old_id] for length, old_id in model.flow_length_to_id.items()},
            id_to_rf={old_to_new[old_id]: rf for old_id, rf in model.id_to_rf.items()}
    )


def slice_model(model: Model, slices_to_dts: List[Set[int]]) -> List[ModelSlice]:
    """
    Slices a model into multiple slices, each containing the specified DTs of all RFs.
    The returned list of model slices is a shallow copy of the original model.

    The returned list has the same length as the input list.
    Each number in the input list corresponds to the DTs that should be included in the corresponding slice:
    the i-th slice in the result will contain the DTs indexed by the number in the i-th position of the input list.
    """
    # Validate that the specified DTs are within bounds
    for rf in model.id_to_rf.values():
        for dt_indexes in slices_to_dts:
            assert all(0 <= i < len(rf.dts) for i in dt_indexes)

    return [
        ModelSlice(
                original=model,
                id_to_rf={rf_id: ModelRFSlice(original=rf,
                                              dts=[rf.dts[i] for i in dt_indexes],
                                              dt_indexes=list(dt_indexes))
                          for rf_id, rf in model.id_to_rf.items()}
        ) for dt_indexes in slices_to_dts
    ]
