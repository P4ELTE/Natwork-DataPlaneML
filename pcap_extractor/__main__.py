import argparse
import logging
import sys
from pathlib import Path
from typing import List, Optional

import dpkt.pcapng
import numpy as np

from lib_common.dataset.label_csv import ImprovedCicidsCsvLoader
from lib_common.flow import Label
from lib_common.model.data import ModelTrainingConfig
from pcap_extractor import logic

_logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--log-level', choices=['debug', 'info'], default='info')
    parser.add_argument('--pcap-path', type=Path, required=True,
                        help="Path to the PCAP file to be processed")
    parser.add_argument('--label-csv-path', type=Path, required=True,
                        help="Path to the CSV file containing labels for the flows in the PCAP file")
    parser.add_argument('--attack-type-whitelist', type=str, default=None,
                        help="Comma-separated list of flow labels to exclusively consider as attacks")
    parser.add_argument('--out-path', type=Path, required=True,
                        help="Path where the exported data should be saved")
    parser.add_argument('--overwrite', action='store_true',
                        help="If set, the output file at --out-path will be overwritten if it already exists")
    args = parser.parse_args()

    logging.basicConfig(force=True, level=args.log_level.upper(),
                        format='[%(asctime)s] %(levelname)s [%(threadName)s] [%(name)s] %(message)s',
                        stream=sys.stdout)

    out_path: Path = args.out_path
    pcap_path: Path = args.pcap_path
    label_csv_path: Path = args.label_csv_path
    out_path_overwrite_enabled: bool = args.overwrite
    attack_type_whitelist = args.attack_type_whitelist.split(',') if args.attack_type_whitelist else None

    start_extractor(pcap_path, label_csv_path, attack_type_whitelist, out_path, out_path_overwrite_enabled)


def start_extractor(pcap_path: Path, label_csv_path: Path, attack_type_whitelist: Optional[List[str]],
                    out_path: Path, out_path_overwrite_enabled: bool) -> None:
    """Starts the extractor component."""
    if not pcap_path.exists():
        _logger.error(f"Input PCAP file '{pcap_path}' does not exist, aborting...")
        sys.exit(1)

    if not label_csv_path.exists():
        _logger.error(f"Input label CSV file '{label_csv_path}' does not exist, aborting...")
        sys.exit(1)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    if out_path.exists() and not out_path_overwrite_enabled:
        _logger.error(f"Output file '{out_path}' already exists, aborting...")
        sys.exit(1)

    _logger.info(f"Processing PCAP file at {pcap_path}...")
    # Determine the max flow length. At the moment all configurations use the same value.
    max_flow_length = ModelTrainingConfig.create_for_centralized().max_classifiable_flow_length
    with pcap_path.open('rb') as pcap_file:
        pcap_reader = dpkt.pcap.UniversalReader(pcap_file)
        flow_data, flow_features = logic.extract_features(max_flow_length, pcap_reader)

    _logger.info(f"Loading labels from CSV file at {label_csv_path}...")
    _logger.info(f"  Attack type whitelist: {attack_type_whitelist}")
    csv_loader = ImprovedCicidsCsvLoader(label_csv_path, attack_type_whitelist)
    flow_true_labels = logic.pair_labels(flow_data, csv_loader.load_flow_to_label())

    _logger.info(f"Exporting collected data containing {len(flow_data)} flows to {out_path}...")
    _logger.info(f"  Exported label stats: {Label.compute_count_statistics(flow_true_labels)}")
    np.savez_compressed(out_path, flow_data=flow_data, flow_features=flow_features, flow_true_labels=flow_true_labels)


if __name__ == '__main__':
    main()
