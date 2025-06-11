import abc
import logging
import pickle
from typing import Dict

import zmq

from lib_common.model.data import Model

_logger = logging.getLogger(__name__)


class ControllerInterfaceHandler(abc.ABC):
    """Class responsible for implementing callbacks required by ControllerInterface."""

    @abc.abstractmethod
    def handle_controller_connected(self, controller_id: str) -> None:
        """
        Handles when a controller has connected to the coordinator.
        """
        pass

    @abc.abstractmethod
    def handle_model_update(self, controller_id: str, model: Model) -> None:
        """
        Handles when a controller sends a refined model to the coordinator.
        """
        pass


class ControllerInterface(abc.ABC):
    """Interface through which the coordinator can communicate with controllers."""

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
    def listen_forever(self, handler: ControllerInterfaceHandler) -> None:
        """
        Listens to incoming communication attempts. This is a blocking method which never returns.
        """
        pass

    @abc.abstractmethod
    def send_model(self, controller_id_to_model: Dict[str, Model]) -> None:
        """
        Sends newly created models to all controllers.
        """
        pass

    @abc.abstractmethod
    def close(self) -> None:
        """Releases any resources held by the interface."""
        pass


class ZmqControllerInterface(ControllerInterface):
    """A controller interface that uses ZeroMQ for communication."""

    def __init__(self, endpoint: str) -> None:
        self._shutdown: bool = False
        self._endpoint = endpoint
        self._context = zmq.Context()
        # noinspection PyTypeChecker
        self._socket: zmq.socket.Socket = None  # Socket must be created in the thread that will use it

    def initialize(self) -> None:
        self._socket = self._context.socket(zmq.ROUTER)
        self._socket.bind(self._endpoint)

    def shutdown(self) -> None:
        self._shutdown = True

    def listen_forever(self, handler: ControllerInterfaceHandler) -> None:
        _logger.debug(f"Listening forever for incoming communication attempts on {self._endpoint}")

        while not self._shutdown:
            # Don't wait indefinitely for a message, so that we can check if we should shut down
            if self._socket.poll(timeout=500) == 0:
                continue

            received_raw = self._socket.recv_multipart()
            controller_id, msg_type, payload = received_raw[0].decode(), received_raw[1], received_raw[2:]
            _logger.debug(f"'{controller_id}' has sent a '{msg_type}' message")
            if msg_type == b"HELLO":
                assert len(payload) == 0
                handler.handle_controller_connected(controller_id)
            elif msg_type == b"MODEL_UPDATE":
                assert len(payload) == 1
                model = pickle.loads(payload[0])  # Future work: better serialization
                handler.handle_model_update(controller_id, model)
            else:
                raise ValueError(f"Unknown message type: {msg_type}")
            _logger.debug(f"Finished handling '{msg_type}' message from '{controller_id}'")

    def send_model(self, controller_id_to_model: Dict[str, Model]) -> None:
        _logger.debug("Sending new model to each controller...")
        for controller_id, model in controller_id_to_model.items():
            self._socket.send_multipart([
                controller_id.encode(),
                pickle.dumps(model)  # Future work: better serialization
            ])
        _logger.debug("New model has been sent to each controller")

    def close(self) -> None:
        self._socket.close(0)
        self._context.term()
