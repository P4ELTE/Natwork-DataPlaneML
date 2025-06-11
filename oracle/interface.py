import abc
import logging

import zmq

from lib_common.flow import ListOfFlowDataSchema, ListOfFeaturesSchema, ListOfLabelSchema
from lib_common.serialization import ndarray_from_bytes, ndarray_to_bytes

_logger = logging.getLogger(__name__)


class ControllerInterfaceHandler(abc.ABC):
    """Class responsible for implementing callbacks required by the controller interface."""

    def handle_flow_classification_request(self, flow_data: ListOfFlowDataSchema,
                                           flow_features: ListOfFeaturesSchema) -> ListOfLabelSchema:
        """
        Classifies the given flows based on their features, possibly also utilizing the given flow data.
        The result is a list of labels, one for each flow.
        When a flow could not be classified, the "not set" label is used, although this should rarely happen.
        """
        pass


class ControllerInterface(abc.ABC):
    """Interface through which the oracle can communicate with a controller."""

    @abc.abstractmethod
    def shutdown(self) -> None:
        """Signals the interface to shut down."""
        pass

    @abc.abstractmethod
    def listen_forever(self, handler: ControllerInterfaceHandler) -> None:
        """
        Listens to incoming requests and responds to them. This is a blocking method which never returns.
        """
        pass

    @abc.abstractmethod
    def close(self) -> None:
        """Releases any resources held by the interface."""
        pass


class ZmqControllerInterface(ControllerInterface):
    """A controller interface that uses ZeroMQ for communication."""

    def __init__(self, address: str) -> None:
        self._shutdown: bool = False
        self._address = address
        self._context = zmq.Context()
        # noinspection PyTypeChecker
        self._socket: zmq.socket.Socket = None  # Socket must be created in the thread that will use it

    def shutdown(self) -> None:
        self._shutdown = True

    def listen_forever(self, handler: ControllerInterfaceHandler) -> None:
        self._socket = self._context.socket(zmq.REP)
        self._socket.bind(self._address)
        _logger.debug(f"Listening forever for incoming requests on {self._address}")

        while not self._shutdown:
            # Don't wait indefinitely for a message, so that we can check if we should shut down
            if self._socket.poll(timeout=500) == 0:
                continue

            flow_data_raw, flow_features_raw = self._socket.recv_multipart()
            _logger.debug("Received flow classification request, calling handler...")
            flow_data, flow_features = ndarray_from_bytes(flow_data_raw), ndarray_from_bytes(flow_features_raw)
            result = handler.handle_flow_classification_request(flow_data, flow_features)
            _logger.debug("Responding with the result...")
            self._socket.send(ndarray_to_bytes(result))
            _logger.debug("Response has been sent")

    def close(self) -> None:
        self._socket.close(0)
        self._context.term()
