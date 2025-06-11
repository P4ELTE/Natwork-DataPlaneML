import argparse
import logging
import os
import sys
from pathlib import Path
from typing import List, Optional

from lib_common.dataset.label_csv import ImprovedCicidsCsvLoader, CachingLabelCsvLoader
from lib_common.utils import handle_sigterm_sigint
from oracle.interface import ZmqControllerInterface
from oracle.logic import LabelCsvMockOracleLogic, StatisticsCollectorOracleLogic

_logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', choices=['debug', 'info'], default='info')
    parser.add_argument('--csv-path', type=Path, required=True,
                        help="Path to the CSV file containing the labels")
    parser.add_argument('--csv-cache-path', type=Path, default=None,
                        help="Path at which to cache the CSV file for subsequent runs")
    parser.add_argument('--attack-type-whitelist', type=str, default=None,
                        help="Comma-separated list of flow labels to exclusively consider as attacks")
    parser.add_argument('--endpoint', type=str, default="tcp://localhost:52001",
                        help="Endpoint at which the oracle should listen for requests")
    args = parser.parse_args()

    logging.basicConfig(force=True, level=args.log_level.upper(),
                        format='[%(asctime)s] %(levelname)s [%(name)s] %(message)s',
                        stream=sys.stdout)

    attack_type_whitelist = args.attack_type_whitelist.split(",") if args.attack_type_whitelist is not None else None
    start_oracle(args.csv_path, args.csv_cache_path, attack_type_whitelist, args.endpoint)


def start_oracle(csv_path: Path, csv_cache_path: Optional[Path], attack_type_whitelist: Optional[List[str]],
                 endpoint: str) -> None:
    _logger.info(f"PID: {os.getpid()}")

    csv_loader = ImprovedCicidsCsvLoader(csv_path, attack_type_whitelist)
    _logger.info(f"Loading CSV file at {csv_path} using"
                 f" {csv_loader.__class__.__module__}.{csv_loader.__class__.__name__}")
    if csv_cache_path is not None:
        csv_loader = CachingLabelCsvLoader(csv_loader, csv_cache_path)
    else:
        _logger.info("No cache path provided, CSV caching is disabled")

    logic = LabelCsvMockOracleLogic(csv_loader)
    _logger.info(f"Using logic implementation named {logic.__class__.__module__}.{logic.__class__.__name__}")
    logic = StatisticsCollectorOracleLogic(logic)
    logic.initialize()

    controller_interface = ZmqControllerInterface(endpoint)
    _logger.info(f"Binding to {endpoint} and entering main loop...")

    try:
        handle_sigterm_sigint(lambda: controller_interface.shutdown())
        controller_interface.listen_forever(logic)
        controller_interface.close()
    finally:
        _logger.info("Main loop has returned, exiting")


if __name__ == "__main__":
    main()
