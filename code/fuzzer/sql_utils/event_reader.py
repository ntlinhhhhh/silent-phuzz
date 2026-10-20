"""Read and classify SQL events written by the request-scoped PHP hook."""
from __future__ import annotations

from dataclasses import dataclass, field
import gzip
import json
from pathlib import Path
import re
import time
from typing import Any, Iterable


class HookEventError(RuntimeError):
    pass


_COVERAGE_ID = re.compile(r"^[A-Za-z0-9_-]{1,200}$")

SQL_SINK_FUNCTIONS = frozenset(
    {
        "mysqli_query",
        "mysqli::query",
        "PDO::query",
        "PDO::exec",
        "mysqli_stmt::execute",
        "mysqli_stmt_execute",
        "PDOStatement::execute",
        "mysqli::multi_query",
        "mysqli_multi_query",
    }
)

def _validate_coverage_id(coverage_id: str) -> str:
    coverage_id = str(coverage_id)
    if not _COVERAGE_ID.fullmatch(coverage_id):
        raise HookEventError("coverage_id contains unsupported characters")
    return coverage_id


@dataclass(frozen=True)
class HookEventRead:
    coverage_id: str
    path: Path
    events: list[dict[str, Any]]
    event_file_observed: bool


class HookEventReader:
    """Read only the event file for one candidate, never infer SQL from HTTP."""

    def __init__(self, directory: str | Path = "/shared-tmpfs/mysql-query-events", *, poll_seconds: float = 0.05):
        if poll_seconds <= 0:
            raise ValueError("poll_seconds must be positive")
        self.directory = Path(directory)
        self.poll_seconds = poll_seconds

    def path_for(self, coverage_id: str) -> Path:
        return self.directory / f"{_validate_coverage_id(coverage_id)}.json"

    def clear(self, coverage_id: str) -> None:
        """Remove only the new candidate's own stale hook-event file."""
        path = self.path_for(coverage_id)
        try:
            path.unlink(missing_ok=True)
        except OSError as error:
            raise HookEventError(f"Could not clear stale query event file {path}: {error}") from error

    @staticmethod
    def _decode(path: Path) -> str:
        try:
            raw = path.read_bytes()
        except OSError as error:
            raise HookEventError(f"Could not read query event file {path}: {error}") from error
        if raw.startswith(b"\x1f\x8b"):
            try:
                raw = gzip.decompress(raw)
            except (OSError, EOFError) as error:
                # The PHP writer may still be appending another gzip member.
                raise HookEventError(f"Compressed query event file is incomplete: {path}") from error
        try:
            return raw.decode("utf-8")
        except UnicodeDecodeError as error:
            raise HookEventError(f"Query event file is not UTF-8: {path}") from error

    @staticmethod
    def _parse(path: Path) -> list[dict[str, Any]]:
        events: list[dict[str, Any]] = []
        for line_number, line in enumerate(HookEventReader._decode(path).splitlines(), start=1):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError as error:
                raise HookEventError(f"Invalid JSON on line {line_number} of {path}") from error
            if not isinstance(event, dict):
                raise HookEventError(f"Query event line {line_number} of {path} is not an object")
            events.append(event)
        return events

    def read(self, coverage_id: str, *, timeout_seconds: float = 1.0) -> HookEventRead:
        if timeout_seconds < 0:
            raise ValueError("timeout_seconds must not be negative")
        coverage_id = _validate_coverage_id(coverage_id)
        path = self.path_for(coverage_id)
        deadline = time.monotonic() + timeout_seconds
        observed = False
        last_error: HookEventError | None = None

        while True:
            if path.exists():
                observed = True
                try:
                    return HookEventRead(
                        coverage_id=coverage_id,
                        path=path,
                        events=self._parse(path),
                        event_file_observed=True,
                    )
                except HookEventError as error:
                    last_error = error

            if time.monotonic() >= deadline:
                if not observed:
                    # An endpoint that makes no SQL call is valid. Do not infer
                    # execution from an HTTP response.
                    return HookEventRead(coverage_id, path, [], False)
                assert last_error is not None
                raise last_error
            time.sleep(self.poll_seconds)


@dataclass
class EventClassification:
    confirmed: list[dict[str, Any]] = field(default_factory=list)
    failures: list[dict[str, Any]] = field(default_factory=list)
    phase_mismatches: list[dict[str, Any]] = field(default_factory=list)
    ignored_count: int = 0

    @property
    def matching_event_count(self) -> int:
        return len(self.confirmed) + len(self.failures)


class HookEventClassifier:
    """Decide AST eligibility from hook evidence only, never HTTP response data."""

    def classify(
        self,
        events: Iterable[dict[str, Any]],
        *,
        coverage_id: str,
        phase: str,
    ) -> EventClassification:
        result = EventClassification()
        for event in events:
            if event.get("current_coverage_id") != coverage_id:
                result.ignored_count += 1
                continue
            if event.get("phase") != phase:
                result.phase_mismatches.append(event)
                continue

            function = event.get("function")

            if function not in SQL_SINK_FUNCTIONS:
                result.ignored_count += 1
                continue
            if event.get("success") is True:
                result.confirmed.append(event)
            else:
                # successful SQL event.
                result.failures.append(event)
        return result
