import dataclasses
from typing import Optional

from lib_common.data import SwitchConstants
from lib_common.model.data import ModelTrainingConfig


@dataclasses.dataclass(frozen=True)
class ModelRefiningConfig:
    """Configuration of how models should be improved."""
    flow_timeout_sec: int = 30  # After how many seconds of inactivity a flow is considered completed
    flow_collection_frequency_millis: int = 300  # How often to collect & classify collectible flows for re-training
    min_recent_flow_count: int = 10  # Training and performance evaluation requires at least this many "recent" flows
    training_flow_time_window_sec: int = 2700  # Last how many seconds of "recent" flows to use as training data
    scoring_flow_time_window_sec: int = 90  # Last how many seconds of "recent" flows to use for performance evaluation
    scoring_flow_age_weight_lerp_max: float = -20.0  # Newer flows get linearly more weight: oldest: *1; newest: *max
    target_latest_flow_f1_score: float = 0.99  # Re-training is not necessary above this F1 score
    acceptable_f1_score_difference: float = 0.01  # Accept new model iff: new_f1 >= min(target_f1, old_f1 + THIS)

    def __post_init__(self) -> None:
        # Sanity-check the configuration
        if self.flow_timeout_sec >= max(self.training_flow_time_window_sec, self.scoring_flow_time_window_sec):
            raise ValueError("Recent flow time windows must be greater than timeout: otherwise no flows are recent")

    @property
    def max_of_flow_time_window_sec(self) -> int:
        """The maximum of the time windows related to the recent flows."""
        return max(self.training_flow_time_window_sec, self.scoring_flow_time_window_sec)


@dataclasses.dataclass(frozen=True)
class StatsDatabaseConfig:
    """Connection parameters, configuration of the database used to store statistics."""
    hostname: str = "http://localhost:8181"
    database_name: str = "natwork-t52"
    # The database is only accessible from the internal network, so sharing the token is not a security issue
    auth_token: str = "apiv3_bOKr0cyMhOpMEyeK87IU4fuXQ-PblibC1u0ni_CXjP52fwgaaAhv5Lm8mmvQt8XyIpK521Iv4YlllmrlUtxXOA"


@dataclasses.dataclass(frozen=True)
class ControllerConfig:
    """Configuration of the controller component."""
    switch: SwitchConstants
    training: ModelTrainingConfig
    refining: ModelRefiningConfig
    stats_db: Optional[StatsDatabaseConfig]
    monitored_flow_ratio: float  # Ratio of flows whose data and features should be collected and used for training
    stats_from_all_flows: bool  # Whether to collect and include all flows in the statistics, despite the monitor ratio
    oracle_endpoint: str = "tcp://localhost:52001"
    coordinator_endpoint: str = "tcp://localhost:52002"
    export_monitoring_data: bool = True  # Enable to export monitoring data to a file for offline processing
