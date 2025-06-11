import argparse
import logging
import os
import sys

from coordinator.interface import ZmqControllerInterface
from coordinator.logic import CoordinatorLogic
from lib_common.utils import handle_sigterm_sigint

_logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', choices=['debug', 'info'], default='info')
    parser.add_argument('--endpoint', type=str, default="tcp://*:52002",
                        help="Endpoint at which the coordinator should listen for requests")
    args = parser.parse_args()

    logging.basicConfig(force=True, level=args.log_level.upper(),
                        format='[%(asctime)s] %(levelname)s [%(name)s] %(message)s',
                        stream=sys.stdout)

    start_coordinator(args.endpoint)


def start_coordinator(endpoint: str) -> None:
    _logger.info(f"PID: {os.getpid()}")

    controller_interface = ZmqControllerInterface(endpoint)
    controller_interface.initialize()
    logic = CoordinatorLogic(controller_interface)
    _logger.info(f"Binding to {endpoint} and entering main loop...")

    try:
        handle_sigterm_sigint(lambda: logic.shutdown())
        controller_interface.listen_forever(logic)
        controller_interface.close()
    finally:
        _logger.info("Main loop has returned, exiting")


if __name__ == '__main__':
    main()
