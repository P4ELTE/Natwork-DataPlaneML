import logging
from typing import List

from coordinator.interface import ControllerInterface, ControllerInterfaceHandler
from lib_common.model.data import Model

_logger = logging.getLogger(__name__)


class CoordinatorLogic(ControllerInterfaceHandler):
    """The main logic of the coordinator component, which is responsible for combining and slicing models."""

    def __init__(self, controller_interface: ControllerInterface) -> None:
        self._controller_interface: ControllerInterface = controller_interface
        self._controllers: List[str] = []

    def shutdown(self) -> None:
        """Signals the coordinator to shut down."""
        _logger.info("Shutting down...")
        self._controller_interface.shutdown()

    def handle_controller_connected(self, controller_id: str) -> None:
        self._controllers.append(controller_id)
        _logger.info(f"Controller '{controller_id}' connected; connected controllers: {', '.join(self._controllers)}")

    def handle_model_update(self, controller_id: str, model: Model) -> None:
        # TODO implement a real coordinator: this is just a temporary no-op coordinator
        self._controller_interface.send_model({controller_id: model})
