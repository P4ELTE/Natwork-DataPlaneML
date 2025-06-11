import abc
import logging
import pickle

import zmq

from lib_common.flow import ListOfFlowDataSchema, ListOfFeaturesSchema, ListOfLabelSchema
from lib_common.model.data import Model
from lib_common.serialization import ndarray_to_bytes, ndarray_from_bytes

_logger = logging.getLogger(__name__)


class OracleInterface(abc.ABC):
    """Interface through which the controller can communicate with the flow classifier oracle."""

    @abc.abstractmethod
    def initialize(self) -> None:
        """
        Initializes the class instance. This method should be called before any other method.
        It is responsible for setting up connections, starting threads, loading data, etc.
        """
        pass

    @abc.abstractmethod
    def request_classification(self, flow_data: ListOfFlowDataSchema,
                               flow_features: ListOfFeaturesSchema) -> ListOfLabelSchema:
        """
        Sends the specified flow features and extra data to the oracle and returns the classification results
        when they arrive (this is a blocking method). The result is a list of labels, one for each flow.
        When a flow could not be classified, the "not set" label is used, although this should rarely happen.
        """
        pass

    @abc.abstractmethod
    def close(self) -> None:
        """Releases any resources held by the interface."""
        pass


class ZmqOracleInterface(OracleInterface):
    """An oracle interface that uses ZeroMQ for communication."""

    def __init__(self, endpoint: str) -> None:
        self._endpoint = endpoint
        self._context = zmq.Context()
        # noinspection PyTypeChecker
        self._socket: zmq.socket.Socket = None  # Socket must be created in the thread that will use it

    def initialize(self) -> None:
        self._socket = self._context.socket(zmq.REQ)
        self._socket.connect(self._endpoint)

    def request_classification(self, flow_data: ListOfFlowDataSchema,
                               flow_features: ListOfFeaturesSchema) -> ListOfLabelSchema:
        _logger.debug(f"Flow classification: sending request containing {len(flow_data)} flows...")
        self._socket.send_multipart([ndarray_to_bytes(flow_data), ndarray_to_bytes(flow_features)])
        _logger.debug(f"Flow classification: request sent, waiting for response...")
        result = ndarray_from_bytes(self._socket.recv())
        _logger.debug(f"Flow classification: response received")
        return result

    def close(self) -> None:
        self._socket.close(0)
        self._context.term()


class CoordinatorInterfaceHandler(abc.ABC):
    """Class responsible for implementing callbacks required by FromCoordinatorInterface."""

    @abc.abstractmethod
    def handle_model_update(self, model: Model) -> None:
        """
        Handles when the coordinator sends new model to be uploaded to the switches.
        """
        pass


class CoordinatorInterface(abc.ABC):
    """Interface through which a controller can communicate with the coordinator."""

    @abc.abstractmethod
    def initialize(self) -> None:
        """
        Initializes the class instance. This method should be called before any other method.
        It is responsible for setting up connections, starting threads, loading data, etc.
        """
        pass

    @abc.abstractmethod
    def shutdown(self) -> None:
        """Signals the interface to shut down."""
        pass

    @abc.abstractmethod
    def listen_with_timeout(self, handler: CoordinatorInterfaceHandler, timeout_millis: int) -> None:
        """
        Receives and handles to incoming requests/commands. Blocks for at most for the specified amount of time.
        """
        pass

    @abc.abstractmethod
    def send_refined_model(self, model: Model) -> None:
        """
        Sends the current, refined model (trained on local data) to the coordinator.
        At a later time, the coordinator will use this model and models received from other domains to create a new
        global model, which it will distribute to all domains.
        """
        pass

    @abc.abstractmethod
    def close(self) -> None:
        """Releases any resources held by the interface."""
        pass


class ZmqCoordinatorInterface(CoordinatorInterface):
    """A coordinator interface that uses ZeroMQ for communication."""

    def __init__(self, endpoint: str, controller_id: str) -> None:
        self._shutdown: bool = False
        self._endpoint: str = endpoint
        self._controller_id: str = controller_id
        self._context: zmq.Context = zmq.Context()
        # noinspection PyTypeChecker
        self._socket: zmq.socket.Socket = None  # Socket must be created in the thread that will use it
        # noinspection PyTypeChecker
        self._socket_poller: zmq.Poller = None  # Create it in the same thread as the socket

    def initialize(self) -> None:
        self._socket = self._context.socket(zmq.DEALER)
        self._socket.setsockopt(zmq.IDENTITY, self._controller_id.encode())
        self._socket.connect(self._endpoint)
        self._socket_poller = zmq.Poller()
        self._socket_poller.register(self._socket, zmq.POLLIN)
        _logger.debug(f"Announcing presence to the coordinator as {self._controller_id}")
        self._socket.send(b"HELLO")  # Check in with the coordinator

    def shutdown(self) -> None:
        self._shutdown = True

    def listen_with_timeout(self, handler: CoordinatorInterfaceHandler, timeout_millis: int) -> None:
        _logger.debug(f"Listening for incoming communication attempts on {self._endpoint} for {timeout_millis} ms...")

        # Determine whether we are able to receive a message
        if timeout_millis <= 1_000:
            if not self._socket.poll(timeout_millis):
                return  # Timeout reached, exit method
        else:
            # Poll in small increments to allow for quick termination in case of interruption
            for _ in range(timeout_millis // 500):
                if self._shutdown or self._socket.poll(500):
                    break  # Shutting down or message received, run code below
            else:
                return  # Timeout reached, exit method

        if self._shutdown:
            return

        model = self._socket.recv_pyobj()  # Future work: better serialization
        _logger.debug("Received model update")
        handler.handle_model_update(model)
        _logger.debug("Model update has been handled")

    def send_refined_model(self, model: Model) -> None:
        _logger.debug("Sending model...")
        self._socket.send_multipart([
            b"MODEL_UPDATE",
            pickle.dumps(model)  # Future work: better serialization
        ])
        _logger.debug("Model has been sent")

    def close(self) -> None:
        self._socket.close(0)
        self._context.term()
