"""Safe, target-scoped persistence for schema and SQL-context artifacts.

This module owns filesystem concerns only: JSON decoding, atomic replacement,
and the cross-process lock shared by a target's artifacts. It does not
interpret a schema or parse SQL.
"""
from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import json
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Any, Callable, Iterable, Iterator, Mapping

try:  # Linux fuzzer containers use flock; keep a small host-dev fallback.
    import fcntl
except ImportError:  # Windows development fallback
    fcntl = None
    import msvcrt


class ArtifactStoreError(RuntimeError):
    """An artifact could not be read, written, or locked safely."""


class ArtifactLockTimeout(ArtifactStoreError):
    pass


class ArtifactPublishDurabilityUnconfirmed(ArtifactStoreError):
    pass


class SQLContextStoreError(ArtifactStoreError):
    pass


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ArtifactStoreError(f"Duplicate JSON key: {key!r}")
        result[key] = value
    return result


def strict_json_object(raw: bytes) -> dict[str, Any]:
    """Decode one JSON object and reject duplicate keys or trailing bytes."""
    try:
        text = raw.decode("utf-8")
        decoder = json.JSONDecoder(object_pairs_hook=_reject_duplicate_keys)
        value, offset = decoder.raw_decode(text)
    except (UnicodeDecodeError, json.JSONDecodeError, ArtifactStoreError) as error:
        raise ArtifactStoreError(f"Invalid JSON artifact: {error}") from error
    if text[offset:].strip():
        raise ArtifactStoreError("JSON artifact contains trailing data")
    if not isinstance(value, dict):
        raise ArtifactStoreError("JSON artifact root must be an object")
    return value


def read_json_object(path: str | Path) -> dict[str, Any]:
    try:
        return strict_json_object(Path(path).read_bytes())
    except OSError as error:
        raise ArtifactStoreError(f"Could not read artifact {path}: {error}") from error


def atomic_write_json(
    path: str | Path,
    value: Mapping[str, Any],
    *,
    temporary_prefix: str = ".artifact-",
    sync_directory: bool = False,
    sort_keys: bool = True,
) -> None:
    """Atomically replace one UTF-8 JSON object without invoking a shell."""
    path = Path(path)
    try:
        payload = (
            json.dumps(value, ensure_ascii=False, sort_keys=sort_keys, indent=2, allow_nan=False) + "\n"
        ).encode("utf-8")
    except (TypeError, ValueError) as error:
        raise ArtifactStoreError(f"Artifact is not valid JSON data: {error}") from error

    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=temporary_prefix,
        suffix=".tmp",
        dir=path.parent,
    )
    temporary = Path(temporary_name)
    replaced = False
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        replaced = True
        if sync_directory:
            try:
                directory_fd = os.open(path.parent, os.O_RDONLY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
            except OSError as error:
                raise ArtifactPublishDurabilityUnconfirmed(str(path)) from error
    finally:
        if not replaced:
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass


@contextmanager
def exclusive_process_lock(lock_path: str | Path, timeout_seconds: float) -> Iterator[None]:
    """Acquire the target artifact lock on Linux and local Windows development."""
    if timeout_seconds <= 0:
        raise ArtifactStoreError("lock_timeout_seconds must be positive")
    lock_path = Path(lock_path)
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    deadline = time.monotonic() + timeout_seconds
    with lock_path.open("a+b") as handle:
        if fcntl is None:
            handle.seek(0, os.SEEK_END)
            if handle.tell() == 0:
                handle.write(b"\0")
                handle.flush()
        while True:
            try:
                if fcntl is not None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                else:
                    handle.seek(0)
                    msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
                break
            except (BlockingIOError, OSError):
                if time.monotonic() >= deadline:
                    raise ArtifactLockTimeout(f"Timed out waiting for {lock_path}")
                time.sleep(min(0.10, max(0.0, deadline - time.monotonic())))
        try:
            yield
        finally:
            if fcntl is not None:
                fcntl.flock(handle.fileno(), fcntl.LOCK_UN)
            else:
                handle.seek(0)
                msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _input_merge_key(item: Mapping[str, Any]) -> tuple[str, int] | None:
    """Identify one new-contract input by its source binding and position."""
    binding = item.get("sql_binding")
    position = item.get("sql_position")
    if binding not in {"inline_literal", "prepared_placeholder"}:
        return None
    if isinstance(position, bool) or not isinstance(position, int) or position < 0:
        return None
    return binding, position


def _input_order_key(item: Mapping[str, Any]) -> tuple[Any, ...]:
    """Keep parser-assigned input IDs in source order with a stable fallback."""
    input_id = str(item.get("input_id") or "")
    match = re.fullmatch(r"s(\d+)", input_id)
    if match:
        return (0, int(match.group(1)), "", 0, "")
    binding = str(item.get("sql_binding") or "")
    position = item.get("sql_position")
    return (
        1,
        0,
        0 if binding == "inline_literal" else 1,
        int(position) if isinstance(position, int) and not isinstance(position, bool) else 0,
        _canonical_json(item),
    )


def _merge_inputs(existing: Any, incoming: Any) -> list[dict[str, Any]]:
    """Merge proven inputs by SQL source position; newer metadata wins."""
    values: dict[tuple[str, int], dict[str, Any]] = {}
    for source in (existing, incoming):
        if not isinstance(source, list):
            continue
        for item in source:
            if not isinstance(item, Mapping):
                continue
            key = _input_merge_key(item)
            if key is not None:
                values[key] = dict(item)
    return sorted(values.values(), key=_input_order_key)


def _statement_structural_key(statement: Mapping[str, Any]) -> str:
    """Identity of one statement under the SQL Template contract."""
    return _canonical_json(
        {
            "statement_index": statement.get("statement_index"),
            "statement_type": statement.get("statement_type"),
            "template": statement.get("template"),
        }
    )


def _execution_structural_key(execution: Mapping[str, Any]) -> tuple[str, ...]:
    """Return the ordered template-based structural key for one execution."""
    statements = execution.get("statements")
    if not isinstance(statements, list):
        return ()
    return tuple(
        _statement_structural_key(statement)
        for statement in statements
        if isinstance(statement, Mapping)
    )


def _merge_context_inputs(existing: dict[str, Any], incoming: Mapping[str, Any]) -> None:
    """Merge current-contract input evidence onto matching executions."""
    existing_executions = existing.get("request_executions")
    incoming_executions = incoming.get("request_executions")
    if not isinstance(existing_executions, list) or not isinstance(incoming_executions, list):
        return

    for incoming_execution in incoming_executions:
        if not isinstance(incoming_execution, Mapping):
            continue
        incoming_statements = incoming_execution.get("statements")
        if not isinstance(incoming_statements, list):
            continue
        incoming_keys = [_statement_structural_key(item) for item in incoming_statements if isinstance(item, Mapping)]
        incoming_execution_key = _execution_structural_key(incoming_execution)
        matching = next(
            (
                candidate
                for candidate in existing_executions
                if isinstance(candidate, dict)
                and _execution_structural_key(candidate) == incoming_execution_key
            ),
            None,
        )
        for candidate in existing_executions:
            if matching is not None:
                break
            if not isinstance(candidate, dict):
                continue
            candidate_statements = candidate.get("statements")
            candidate_keys = [
                _statement_structural_key(item)
                for item in candidate_statements
                if isinstance(item, Mapping)
            ] if isinstance(candidate_statements, list) else []
            if candidate_keys == incoming_keys:
                matching = candidate
                break
        if matching is None:
            appended = dict(incoming_execution)
            used_indices = {
                int(item.get("execution_index"))
                for item in existing_executions
                if isinstance(item, Mapping)
                and isinstance(item.get("execution_index"), int)
            }
            requested_index = appended.get("execution_index")
            if isinstance(requested_index, int) and requested_index in used_indices:
                appended["execution_index"] = max(used_indices, default=-1) + 1
            existing_executions.append(appended)
            continue

        existing_statements = matching.get("statements")
        if not isinstance(existing_statements, list):
            continue
        by_index = {
            int(statement.get("statement_index", -1)): statement
            for statement in existing_statements
            if isinstance(statement, dict)
        }
        for statement in incoming_statements:
            if not isinstance(statement, Mapping):
                continue
            target = by_index.get(int(statement.get("statement_index", -1)))
            if target is None:
                continue
            incoming_inputs = statement.get("inputs", [])
            if isinstance(incoming_inputs, list):
                target["inputs"] = _merge_inputs(target.get("inputs", []), incoming_inputs)
            for key in ("sink", "sql_raw", "template"):
                value = statement.get(key)
                if isinstance(value, str):
                    target[key] = value

            if "repeat_count" in statement:
                target["repeat_count"] = statement["repeat_count"]


def _execution_statement_shape(execution: Mapping[str, Any]) -> tuple[str, ...]:
    return _execution_structural_key(execution)


def _deduplicate_context_executions(contexts: Any) -> bool:
    """Collapse repeated executions inside an already identified context."""
    if not isinstance(contexts, list):
        return False
    changed = False
    for context in contexts:
        if not isinstance(context, dict):
            continue
        executions = context.get("request_executions")
        if not isinstance(executions, list):
            continue
        representatives: dict[tuple[str, ...], dict[str, Any]] = {}
        positions: dict[tuple[str, ...], int] = {}
        retained: list[Any] = []
        context_changed = False
        for candidate in executions:
            if not isinstance(candidate, dict):
                retained.append(candidate)
                continue
            shape = _execution_statement_shape(candidate)
            if not shape or shape not in representatives:
                if shape:
                    representatives[shape] = candidate
                    positions[shape] = len(retained)
                retained.append(candidate)
                continue

            current = representatives[shape]
            holder = {"request_executions": [current]}
            _merge_context_inputs(holder, {"request_executions": [candidate]})
            merged = holder["request_executions"][0]
            merged["execution_index"] = current.get("execution_index", 0)
            retained[positions[shape]] = merged
            representatives[shape] = merged
            changed = True
            context_changed = True
        if context_changed or len(retained) != len(executions):
            context["request_executions"] = retained
        if len(retained) != len(executions):
            changed = True
    return changed


def normalize_config_reference(config_reference: str) -> str:
    value = str(config_reference).replace("\\", "/").strip()
    if value.endswith(".json"):
        value = value[:-5]
    if not value or value.startswith("/") or any(part in {"", ".", ".."} for part in value.split("/")):
        raise SQLContextStoreError("config reference must be a relative config path")
    return value


def sql_context_file_name(config_reference: str) -> str:
    normalized = normalize_config_reference(config_reference)
    stem = re.sub(r"[^A-Za-z0-9._-]+", "-", normalized.replace("/", "-"))
    stem = stem.strip(".-")
    if not stem:
        raise SQLContextStoreError("config reference cannot produce an empty context filename")
    return f"sql-context-{stem}.json"


@dataclass(frozen=True)
class SQLContextStoreResult:
    path: Path
    added: int
    total: int
    new_context_ids: tuple[str, ...] = ()
    duplicate_contexts: int = 0
    removed_contexts: int = 0


class SQLContextStore:
    """Persist de-duplicated template-based contexts for one config under the target lock."""

    def __init__(self, directory: str | Path, lock_path: str | Path, *, lock_timeout_seconds: float = 30.0):
        if lock_timeout_seconds <= 0:
            raise ValueError("lock_timeout_seconds must be positive")
        self.directory = Path(directory)
        self.lock_path = Path(lock_path)
        self.lock_timeout_seconds = lock_timeout_seconds

    def path_for(self, config_reference: str) -> Path:
        return self.directory / sql_context_file_name(config_reference)

    @staticmethod
    def _new_document(config_reference: str, schema_fingerprint: str) -> dict[str, Any]:
        return {
            "config": normalize_config_reference(config_reference),
            "contexts": [],
            "schema_fingerprint": schema_fingerprint,
        }

    @staticmethod
    def _validate_input(sql_input: Mapping[str, Any]) -> None:
        if set(sql_input) != {
            "input_id",
            "parameter",
            "column",
            "type_family",
            "sql_binding",
            "sql_position",
            "quoted_in_sql",
            "paren_depth",
        }:
            raise SQLContextStoreError("SQL context input has unsupported fields")
        if not isinstance(sql_input.get("input_id"), str) or not re.fullmatch(r"s\d+", sql_input["input_id"]):
            raise SQLContextStoreError("SQL context input input_id must be s<index>")
        parameter = sql_input.get("parameter")
        column = sql_input.get("column")
        if not isinstance(parameter, Mapping) or set(parameter) != {"location", "name"}:
            raise SQLContextStoreError("SQL context input has an invalid parameter")
        if not all(isinstance(parameter.get(key), str) and parameter[key] for key in ("location", "name")):
            raise SQLContextStoreError("SQL context input parameter must be non-empty")
        expected_column_keys = {"schema", "table", "column", "data_type", "column_type"}
        if not isinstance(column, Mapping) or set(column) != expected_column_keys:
            raise SQLContextStoreError("SQL context input has an invalid column")
        if not all(isinstance(column.get(key), str) for key in expected_column_keys):
            raise SQLContextStoreError("SQL context input column fields must be strings")
        if not str(column.get("table") or "") or not str(column.get("column") or ""):
            raise SQLContextStoreError("SQL context input column must identify a table and column")
        if not isinstance(sql_input.get("type_family"), str):
            raise SQLContextStoreError("SQL context input type_family must be a string")
        if sql_input.get("sql_binding") not in {"inline_literal", "prepared_placeholder"}:
            raise SQLContextStoreError("SQL context input sql_binding is invalid")
        if not isinstance(sql_input.get("quoted_in_sql"), bool):
            raise SQLContextStoreError("SQL context input quoted_in_sql must be boolean")
        sql_position = sql_input.get("sql_position")
        if isinstance(sql_position, bool) or not isinstance(sql_position, int) or sql_position < 0:
            raise SQLContextStoreError("SQL context input sql_position must be a non-negative integer")
        paren_depth = sql_input.get("paren_depth")
        if isinstance(paren_depth, bool) or not isinstance(paren_depth, int) or paren_depth < 0:
            raise SQLContextStoreError("SQL context input paren_depth must be a non-negative integer")

    @classmethod
    def _validate_context(cls, context: Mapping[str, Any]) -> None:
        keys = set(context)
        if not (keys == {"sql_context_id", "phuzz_config", "request_executions"} or keys == {"sql_context_id", "endpoint", "request_executions"}):
            raise SQLContextStoreError("SQL context must contain sql_context_id, phuzz_config, request_executions")
        context_id = context.get("sql_context_id")
        if not isinstance(context_id, str) or not context_id:
            raise SQLContextStoreError("SQL context contains an invalid sql_context_id")
        cfg = context.get("phuzz_config") or context.get("endpoint")
        if not isinstance(cfg, Mapping) or not ({"method", "path"}.issubset(set(cfg))):
            raise SQLContextStoreError("SQL context phuzz_config has invalid structure")
        if not isinstance(cfg.get("method"), str) or not isinstance(cfg.get("path"), str):
            raise SQLContextStoreError("SQL context phuzz_config fields must be strings")
        executions = context.get("request_executions")
        if not isinstance(executions, list) or not executions:
            raise SQLContextStoreError("SQL context request_executions must be a non-empty list")
        execution_indices: set[int] = set()
        for execution in executions:
            if not isinstance(execution, Mapping) or set(execution) != {"execution_index", "statements"}:
                raise SQLContextStoreError("SQL context contains an invalid request execution")
            execution_index = execution.get("execution_index")
            if (
                isinstance(execution_index, bool)
                or not isinstance(execution_index, int)
                or execution_index < 0
                or execution_index in execution_indices
            ):
                raise SQLContextStoreError("execution_index must be a unique non-negative integer")
            execution_indices.add(execution_index)
            statements = execution.get("statements")
            if not isinstance(statements, list) or not statements:
                raise SQLContextStoreError("request execution statements must be a non-empty list")
            statement_indices: set[int] = set()
            for statement in statements:
                if not isinstance(statement, Mapping):
                    raise SQLContextStoreError("SQL context contains an invalid statement")
                expected_statement_keys = {
                    "statement_index",
                    "repeat_count",
                    "sink",
                    "statement_type",
                    "sql_raw",
                    "template",
                    "inputs",
                }
                if set(statement) != expected_statement_keys:
                    raise SQLContextStoreError("SQL context statement has unsupported fields")
                index = statement.get("statement_index")
                if isinstance(index, bool) or not isinstance(index, int) or index < 0 or index in statement_indices:
                    raise SQLContextStoreError("SQL context statement_index must be a unique non-negative integer")
                statement_indices.add(index)
                if not isinstance(statement.get("sink"), str) or not statement["sink"]:
                    raise SQLContextStoreError("SQL context statement sink must be non-empty")
                if not isinstance(statement.get("statement_type"), str) or not statement["statement_type"]:
                    raise SQLContextStoreError("SQL context statement_type must be non-empty")
                if not isinstance(statement.get("sql_raw"), str):
                    raise SQLContextStoreError("SQL context sql_raw must be a string")
                if not isinstance(statement.get("template"), str):
                    raise SQLContextStoreError("SQL context template must be a string")
                inputs = statement.get("inputs")
                if not isinstance(inputs, list):
                    raise SQLContextStoreError("SQL context inputs must be a list")
                for sql_input in inputs:
                    if not isinstance(sql_input, Mapping):
                        raise SQLContextStoreError("SQL context contains an invalid input")
                    cls._validate_input(sql_input)
            if statement_indices != set(range(len(statements))):
                raise SQLContextStoreError("statement_index must start at zero and follow request order")

    @classmethod
    def _validate_document(cls, document: Mapping[str, Any], config_reference: str, schema_fingerprint: str) -> None:
        if set(document) != {"config", "schema_fingerprint", "contexts"}:
            raise SQLContextStoreError("SQL context document has unsupported fields")
        if document.get("config") != normalize_config_reference(config_reference):
            raise SQLContextStoreError("SQL context file belongs to a different config")
        if document.get("schema_fingerprint") != schema_fingerprint:
            raise SQLContextStoreError(
                "SQL context was built from a different schema; create a new target artifact directory"
            )
        contexts = document.get("contexts")
        if not isinstance(contexts, list):
            raise SQLContextStoreError("SQL context contexts must be a list")
        ids: set[str] = set()
        for context in contexts:
            if not isinstance(context, Mapping):
                raise SQLContextStoreError("SQL context contains an invalid context")
            cls._validate_context(context)
            context_id = str(context["sql_context_id"])
            if context_id in ids:
                raise SQLContextStoreError(f"SQL context contains duplicate sql_context_id {context_id}")
            ids.add(context_id)

    @classmethod
    def _prepare_document(
        cls,
        document: Mapping[str, Any],
        config_reference: str,
        schema_fingerprint: str,
    ) -> tuple[dict[str, Any], bool]:
        expected_config = normalize_config_reference(config_reference)
        if document.get("config") != expected_config:
            raise SQLContextStoreError("SQL context file belongs to a different config")
        if document.get("schema_fingerprint") != schema_fingerprint:
            raise SQLContextStoreError(
                "SQL context was built from a different schema; create a new target artifact directory"
            )
        prepared = dict(document)
        cls._validate_document(prepared, config_reference, schema_fingerprint)
        return prepared, False

    @staticmethod
    def _load(path: Path) -> dict[str, Any]:
        try:
            return read_json_object(path)
        except ArtifactStoreError as error:
            raise SQLContextStoreError(f"Could not read SQL context {path}: {error}") from error

    @staticmethod
    def _save(path: Path, document: Mapping[str, Any]) -> None:
        try:
            atomic_write_json(
                path,
                document,
                temporary_prefix=".sql-context-",
                sort_keys=False,
            )
        except ArtifactStoreError as error:
            raise SQLContextStoreError(f"Could not save SQL context {path}: {error}") from error

    def initialize(self, config_reference: str, schema_fingerprint: str) -> SQLContextStoreResult:
        return self.upsert(config_reference, schema_fingerprint, [])

    def retain(
        self,
        config_reference: str,
        schema_fingerprint: str,
        keep_context: Callable[[Mapping[str, Any]], bool],
    ) -> SQLContextStoreResult:
        """Remove derived contexts rejected by the current parser policy."""
        if not isinstance(schema_fingerprint, str) or not schema_fingerprint:
            raise SQLContextStoreError("schema_fingerprint is required")
        path = self.path_for(config_reference)
        self.directory.mkdir(parents=True, exist_ok=True)
        with exclusive_process_lock(self.lock_path, self.lock_timeout_seconds):
            existed = path.exists()
            raw_document = self._load(path) if existed else self._new_document(config_reference, schema_fingerprint)
            document, rewritten = self._prepare_document(raw_document, config_reference, schema_fingerprint)
            retained: list[Mapping[str, Any]] = []
            for context in document["contexts"]:
                try:
                    if keep_context(context):
                        retained.append(context)
                except Exception as error:
                    raise SQLContextStoreError("Could not apply SQL-context retention policy") from error
            removed = len(document["contexts"]) - len(retained)
            if removed:
                document["contexts"] = retained
            deduplicated = _deduplicate_context_executions(document["contexts"])
            if removed or rewritten or deduplicated or not existed:
                self._save(path, document)
            return SQLContextStoreResult(
                path=path,
                added=0,
                total=len(retained),
                removed_contexts=removed,
            )

    def upsert(
        self,
        config_reference: str,
        schema_fingerprint: str,
        contexts: Iterable[Mapping[str, Any]],
    ) -> SQLContextStoreResult:
        if not isinstance(schema_fingerprint, str) or not schema_fingerprint:
            raise SQLContextStoreError("schema_fingerprint is required")
        path = self.path_for(config_reference)
        incoming = [dict(context) for context in contexts]
        for context in incoming:
            self._validate_context(context)

        self.directory.mkdir(parents=True, exist_ok=True)
        with exclusive_process_lock(self.lock_path, self.lock_timeout_seconds):
            raw_document = self._load(path) if path.exists() else self._new_document(config_reference, schema_fingerprint)
            document, _rewritten = self._prepare_document(raw_document, config_reference, schema_fingerprint)
            _deduplicate_context_executions(document["contexts"])
            by_id = {context["sql_context_id"]: context for context in document["contexts"]}
            added = 0
            new_context_ids: list[str] = []
            duplicate_contexts = 0
            for context in incoming:
                context_id = context["sql_context_id"]
                existing = by_id.get(context_id)
                if existing is None:
                    by_id[context_id] = context
                    added += 1
                    new_context_ids.append(context_id)
                else:
                    _merge_context_inputs(existing, context)
                    duplicate_contexts += 1
            document["contexts"] = [by_id[context_id] for context_id in sorted(by_id)]
            _deduplicate_context_executions(document["contexts"])
            self._save(path, document)
            return SQLContextStoreResult(
                path=path,
                added=added,
                total=len(document["contexts"]),
                new_context_ids=tuple(new_context_ids),
                duplicate_contexts=duplicate_contexts,
            )