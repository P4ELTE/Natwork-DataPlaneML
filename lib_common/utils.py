import logging
import signal
import time
from logging import Logger
from typing import Callable, Literal

_logger = logging.getLogger(__name__)


class PerfReporter:
    """
    Keeps track of how fast specific segments of the code finish, periodically reporting the results.
    The internal data is cleared whenever a report is made.
    Compatible with the `with` statement.

    Instances should only be created using the static methods.
    """

    def __init__(self, report_every_n_call: int, reporter: Callable[['PerfReporter'], None]) -> None:
        assert report_every_n_call > 0, "The report frequency must be a positive number."
        self._report_every_n_call = report_every_n_call
        self._reporter = reporter
        self._count, self._min, self._max, self._sum = 0, float('inf'), 0.0, 0.0
        self._start_time: int = -1

    @staticmethod
    def _create(report_every_n_call: int, logger: Logger, measured_task_name: str, unit: Literal['millis', 'micros'],
                value_divisor: float) -> 'PerfReporter':
        """Creates a new instance, taking care of the formatting and unit conversion."""
        if report_every_n_call == 1:
            def report(x: 'PerfReporter') -> None:
                logger.debug(f"Delta time of {measured_task_name}: {x._sum / value_divisor:.0f} {unit}")
        else:
            def report(x: 'PerfReporter') -> None:
                logger.debug(f"Delta time of {measured_task_name} in {unit}:"
                             f" min={x._min / value_divisor:.0f}; max={x._max / value_divisor:.0f};"
                             f" avg={x._sum / x._count / value_divisor:.0f}")
        return PerfReporter(report_every_n_call, report)

    @staticmethod
    def millis(report_every_n_call: int, logger: Logger, measured_task_name: str) -> 'PerfReporter':
        """Creates a new instance that reports the time in milliseconds."""
        return PerfReporter._create(report_every_n_call, logger, measured_task_name,
                                    'millis', 1_000_000)

    @staticmethod
    def micros(report_every_n_call: int, logger: Logger, measured_task_name: str) -> 'PerfReporter':
        """Creates a new instance that reports the time in microseconds."""
        return PerfReporter._create(report_every_n_call, logger, measured_task_name,
                                    'micros', 1_000)

    def __enter__(self) -> None:
        self.start()

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.stop()

    def start(self) -> None:
        """Begins counting the time."""
        self._start_time = time.time_ns()

    def stop(self) -> None:
        """Stops counting the time, saves the result and potentially makes a report."""
        delta_nanos = time.time_ns() - self._start_time
        self._count += 1
        self._min = min(self._min, delta_nanos)
        self._max = max(self._max, delta_nanos)
        self._sum += delta_nanos

        # Make a report if necessary
        if self._count % self._report_every_n_call == 0:
            self._reporter(self)
            self._count, self._min, self._max, self._sum = 0, float('inf'), 0.0, 0.0


def handle_sigterm_sigint(callback: Callable[[], None]) -> None:
    """
    Registers a callback to be executed when a SIGTERM or a SIGINT signal is received.
    Useful for implementing a graceful shutdown of the application.
    """

    def signal_handler(_sig, _frame) -> None:
        _logger.info(f"{signal.Signals(_sig).name} received")
        callback()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
