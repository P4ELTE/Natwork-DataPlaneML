import io
from typing import Any

import numpy as np


def ndarray_to_bytes(array: np.ndarray) -> bytes:
    """
    Converts a numpy array to a bytes object.
    Not only the data is serialized, but also the shape and dtype of the array.
    """
    buffer = io.BytesIO()
    ndarray_to_io(buffer, array)
    return buffer.getvalue()


def ndarray_from_bytes(raw: bytes) -> np.ndarray:
    """Inverse operation of ndarray_to_bytes."""
    buffer = io.BytesIO(raw)
    buffer.seek(0)
    return ndarray_from_io(buffer)


def ndarray_to_io(file_like: Any, array: np.ndarray) -> None:
    """Saves a ndarray to a file-like object. Works just like ndarray_to_bytes, but writes directly to IO."""
    np.save(file_like, array, allow_pickle=False)  # Disallow pickling to avoid security risks
    return file_like.getvalue()


def ndarray_from_io(file_like: Any) -> np.ndarray:
    """Loads a ndarray from a file-like object. Works just like ndarray_from_bytes, but reads directly from IO."""
    return np.load(file_like, allow_pickle=False)
