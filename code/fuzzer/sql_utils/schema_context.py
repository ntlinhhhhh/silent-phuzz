"""Collect, validate, fingerprint, and publish MySQL schema contexts.

Everything here has a schema-context input or output.  Generic file locking
and atomic JSON replacement live in artifact_store.py so SQL-context artifacts
can reuse the same safe persistence mechanism.
"""
from __future__ import annotations

from collections import defaultdict
from contextlib import closing
import copy
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any, Mapping

from sql_utils.artifact_store import ArtifactStoreError, atomic_write_json, exclusive_process_lock, read_json_object

class SchemaContextError(RuntimeError):
    """A schema context is invalid, unstable or cannot be collected."""

class SchemaChangedDuringCollection(SchemaContextError):
    pass

class InvalidSchemaContext(SchemaContextError):
    pass

class SchemaCollectionError(SchemaContextError):
    pass

@dataclass(frozen=True)
class DatabaseSettings:
    """Database connection settings for schema collection and instrumentation verification."""
    host: str
    port: int
    user: str
    password: str
    database: str
    connect_timeout_seconds: int = 10

    @classmethod
    def from_environment(cls, eviron: Mapping[str, str]| None = None) -> DatabaseSettings:
        """Create a DatabaseSettings object from environment variables."""
        values = os.environ if eviron is None else eviron
        try:
            port = int(values.get("SCHEMA_DB_PORT") or values.get("PHUZZ_DB_PORT", "3306")) 
            timeout = int(values.get("PHUZZ_DB_CONNECT_TIMEOUT", "10"))
        except ValueError as error:
            raise SchemaContextError("SCHEMA_DB_PORT and SCHEMA_DB_CONNECT_TIMEOUT must be integers") from error
        if not 1 <= port <= 65535:
            raise SchemaCollectionError("SCHEMA_DB_PORT must be between 1 and 65535")
        if timeout <= 0:
            raise SchemaCollectionError("SCHEMA_DB_CONNECT_TIMEOUT must be positive")

        database = values.get("SCHEMA_DB_NAME") or values.get("MYSQL_DATABASE") or "db"
        return cls(
            host=values.get("SCHEMA_DB_HOST", "db"),
            port=port,
            user=values.get("SCHEMA_DB_USER", "user"),
            password=values.get("SCHEMA_DB_PASSWORD", "password"),
            database=database,
            connect_timeout_seconds=timeout,
        )

@dataclass(frozen=True)
class ResolvedForeignKey:
    """Safe reference to a foreign key in a schema context, used for resolving foreign key relationships."""
    schema: str
    table: str
    column: str

@dataclass(frozen=True)
class ColumnConstraints:
    """Constraints on a column in a schema context."""
    type_family: str
    data_type: str
    signed: bool | None
    numeric_precision: int | None
    numeric_scale: int | None
    max_length: int | None
    enum_values: tuple[str, ...]
    nullable: bool
    foreign_key: ResolvedForeignKey | None
    checks: tuple[str, ...]

def _required_target_id(value: str) -> str:
    value = str(value).strip()
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", value):
        raise SchemaCollectionError(
            "target_id must contain only letters, digits, '.', '_' or '-' "
            "and must not contain a path separator"
        )
    return value

@dataclass(frozen=True)
class ArtifactPaths:
    root: Path
    target_id: str

    @classmethod
    def create(cls, artifact_root: str | Path, target_id: str) -> "ArtifactPaths":
        return cls(Path(artifact_root), _required_target_id(target_id))

    @property
    def target_root(self) -> Path:
        return self.root / self.target_id

    @property
    def schema_file(self) -> Path:
        """Đường dẫn duy nhất tới file schema_context.json."""
        return self.target_root / "schema_context.json"

    @property
    def snapshot_file(seft) -> Path:
        return seft.target_root / "snapshot.sql"
    @property
    def lock(self) -> Path:
        return self.target_root / "schema-context.lock"

    @property
    def sql_context_dir(self) -> Path:
        return self.target_root / "sql-context"

def _query_rows(connection: Any, sql: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    """Run one bound metadata query and normalize only dictionary key casing."""
    cursor = connection.cursor()
    try:
        cursor.execute(sql, params)
        rows = cursor.fetchall()
    finally:
        cursor.close()

    normalized: list[dict[str, Any]] = []
    for row in rows:
        result: dict[str, Any] = {}
        for key, value in row.items():
            lowered = str(key).lower()
            if lowered in result:
                raise SchemaContextError(f"Metadata row has colliding keys: {key!r}")
            result[lowered] = value
        normalized.append(result)
    return normalized

def _table_key(schema: str, table: str) -> str:
    return json.dumps([schema, table], ensure_ascii=False, separators=(",", ":"))

def _require_schema_json(value: Any, path: str = "$") -> None:
    """Schema artifacts intentionally exclude floats and non-JSON values."""
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        raise InvalidSchemaContext(f"Float is not permitted in schema JSON at {path}")
    if isinstance(value, list):
        for index, item in enumerate(value):
            _require_schema_json(item, f"{path}[{index}]")
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise InvalidSchemaContext(f"Non-string JSON key at {path}")
            _require_schema_json(item, f"{path}.{key}")
        return
    raise InvalidSchemaContext(f"Unsupported JSON value {type(value).__name__} at {path}")

def _compact_json(value: Any) -> str:
    _require_schema_json(value)
    return json.dumps(value, ensure_ascii=False, allow_nan=False, sort_keys=True, separators=(",", ":"))


def _sort_named(items: list[dict[str, Any]], field: str) -> list[dict[str, Any]]:
    return sorted(items, key=lambda item: (str(item.get(field, "")), _compact_json(item)))

def _canonical_table(table: dict[str, Any]) -> dict[str, Any]:
    """Sort only lists whose member order has no SQL meaning."""
    result = copy.deepcopy(table)
    for list_name, name_field in (
        ("unique_keys", "name"),
        ("foreign_keys", "name"),
        ("checks", "name"),
        ("indexes", "name"),
        ("triggers", "trigger_name"),
    ):
        result[list_name] = _sort_named(list(result.get(list_name, [])), name_field)
    # Do not sort column_order, primary_key, FK columns, referenced_columns,
    # or index.parts: each of those orders has SQL semantics.
    return result

def canonical_schema_context(context: Mapping[str, Any]) -> dict[str, Any]:
    """Return the stable subset of a schema context used for its fingerprint."""
    required = (
        "format_version",
        "fingerprint_version",
        "dbms",
        "database",
        "lower_case_table_names",
        "tables",
    )
    missing = [key for key in required if key not in context]
    if missing:
        raise InvalidSchemaContext(f"Fingerprint payload is missing: {missing}")
    tables = context["tables"]
    if not isinstance(tables, dict):
        raise InvalidSchemaContext("tables must be an object")
    return {
        key: (
            {_table_key: _canonical_table(tables[_table_key]) for _table_key in sorted(tables)}
            if key == "tables"
            else context[key]
        )
        for key in required
    }

def schema_fingerprint(context: Mapping[str, Any]) -> str:
    payload = canonical_schema_context(context)
    encoded = _compact_json(payload).encode("utf-8")
    digest = hashlib.sha256(b"phuzz/schema-context/v1\0" + encoded).hexdigest()
    return f"sha256:{digest}"


QUERIES = {
    "tables": """SELECT table_schema, table_name, table_type, engine, table_collation
        FROM information_schema.tables WHERE table_schema = %s ORDER BY table_name""",
    "columns": """SELECT table_schema, table_name, column_name, ordinal_position,
        is_nullable, data_type, column_type, column_default, extra,
        character_maximum_length, character_octet_length, numeric_precision,
        numeric_scale, datetime_precision, character_set_name, collation_name,
        generation_expression, column_comment
        FROM information_schema.columns WHERE table_schema = %s
        ORDER BY table_name, ordinal_position""",
    "keys": """SELECT table_schema, table_name, constraint_name, column_name,
        ordinal_position, referenced_table_schema, referenced_table_name,
        referenced_column_name FROM information_schema.key_column_usage
        WHERE table_schema = %s ORDER BY table_name, constraint_name, ordinal_position""",
    "references": """SELECT constraint_schema, table_name, constraint_name,
        update_rule, delete_rule FROM information_schema.referential_constraints
        WHERE constraint_schema = %s ORDER BY table_name, constraint_name""",
    "checks": """SELECT t.table_schema, t.table_name, t.constraint_name, t.enforced,
        c.check_clause FROM information_schema.table_constraints AS t
        JOIN information_schema.check_constraints AS c
          ON c.constraint_schema = t.constraint_schema
         AND c.constraint_name = t.constraint_name
        WHERE t.table_schema = %s AND t.constraint_type = 'CHECK'
        ORDER BY t.table_name, t.constraint_name""",
    "indexes": """SELECT table_schema, table_name, index_name, non_unique,
        seq_in_index, column_name, expression, sub_part, collation, index_type,
        is_visible FROM information_schema.statistics WHERE table_schema = %s
        ORDER BY table_name, index_name, seq_in_index""",
    "triggers": """SELECT trigger_schema AS table_schema,
        event_object_table AS table_name, trigger_name, event_manipulation,
        action_timing, action_order, action_statement, definer, sql_mode,
        character_set_client, collation_connection
        FROM information_schema.triggers WHERE trigger_schema = %s
        ORDER BY event_object_table, trigger_name""",
}

def read_server_settings(connection: Any) -> dict[str, Any]:
    row = _query_rows(
        connection,
        """SELECT VERSION() AS server_version,
        @@SESSION.sql_mode AS sql_mode,
        @@GLOBAL.lower_case_table_names AS lower_case_table_names""",
    )[0]
    version = str(row["server_version"])
    match = re.match(r"(\d+)\.(\d+)\.(\d+)", version)
    if not match or "mariadb" in version.lower():
        raise SchemaContextError(f"Unsupported database server: {version}")
    if tuple(map(int, match.groups())) < (8, 0, 16):
        raise SchemaContextError(f"MySQL >= 8.0.16 is required, got {version}")
    return row

def build_schema_context(
    database: str,
    metadata: dict[str, list[dict[str, Any]]],
    settings: dict[str, Any],
    captured_at: str,
) -> dict[str, Any]:
    missing = set(QUERIES) - set(metadata)
    if missing:
        raise InvalidSchemaContext(f"Missing metadata groups: {sorted(missing)}")
    modes = str(settings.get("sql_mode") or "").split(",")
    context: dict[str, Any] = {
        "format_version": 1,
        "fingerprint_version": 1,
        "dbms": "MySQL",
        "database": database,
        "server_version": str(settings["server_version"]),
        "collector_session": {"sql_mode": sorted(mode for mode in modes if mode)},
        "lower_case_table_names": int(settings["lower_case_table_names"]),
        "captured_at": captured_at,
        "coverage": "Objects visible to metadata account; excludes temporary tables",
        "tables": {},
    }
    tables: dict[str, dict[str, Any]] = context["tables"]
    for row in metadata["tables"]:
        key = _table_key(row["table_schema"], row["table_name"])
        if key in tables:
            raise InvalidSchemaContext(f"Duplicate table metadata: {key}")
        tables[key] = {
            "schema": row["table_schema"],
            "name": row["table_name"],
            "kind": row["table_type"],
            "engine": row.get("engine"),
            "collation": row.get("table_collation"),
            "columns": {},
            "column_order": [],
            "primary_key": [],
            "unique_keys": [],
            "foreign_keys": [],
            "checks": [],
            "indexes": [],
            "triggers": [],
        }

    def target(row: dict[str, Any]) -> dict[str, Any]:
        key = _table_key(row["table_schema"], row["table_name"])
        if key not in tables:
            raise InvalidSchemaContext(f"Metadata refers to missing table: {key}")
        return tables[key]

    def int_or_none(value: Any) -> int | None:
        return None if value is None else int(value)

    for row in metadata["columns"]:
        table = target(row)
        extra = str(row.get("extra") or "")
        generated = bool(row.get("generation_expression")) or any(
            term in extra.upper() for term in ("VIRTUAL GENERATED", "STORED GENERATED")
        )
        name = row["column_name"]
        if name in table["columns"]:
            raise InvalidSchemaContext(f"Duplicate column metadata: {table['name']}.{name}")
        nullable = row["is_nullable"] == "YES"
        raw_default = row.get("column_default")
        default_kind = (
            "generated_expression"
            if "DEFAULT_GENERATED" in extra.upper()
            else "literal"
            if raw_default is not None
            else "null_or_unspecified"
        )
        column = {
            "name": name,
            "ordinal": int(row["ordinal_position"]),
            "data_type": str(row["data_type"]).lower(),
            "column_type": row["column_type"],
            "nullable": nullable,
            "default": raw_default,
            "default_kind": default_kind,
            "extra": extra,
            "auto_increment": "auto_increment" in extra.lower(),
            "generated": generated,
            "invisible": "INVISIBLE" in extra.upper(),
            "required_on_insert": not nullable
            and row.get("column_default") is None
            and "auto_increment" not in extra.lower()
            and not generated,
            "character_maximum_length": int_or_none(row.get("character_maximum_length")),
            "character_octet_length": int_or_none(row.get("character_octet_length")),
            "numeric_precision": int_or_none(row.get("numeric_precision")),
            "numeric_scale": int_or_none(row.get("numeric_scale")),
            "datetime_precision": int_or_none(row.get("datetime_precision")),
            "character_set_name": row.get("character_set_name"),
            "collation_name": row.get("collation_name"),
            "generation_expression": row.get("generation_expression"),
            "column_comment": row.get("column_comment"),
        }
        table["columns"][name] = column

    for table in tables.values():
        if not table["columns"]:
            raise InvalidSchemaContext(f"No visible column metadata: {table['name']}")
        table["column_order"] = [
            column["name"] for column in sorted(table["columns"].values(), key=lambda column: column["ordinal"])
        ]

    reference_rules = {
        (row["constraint_schema"], row["table_name"], row["constraint_name"]): row
        for row in metadata["references"]
    }
    key_groups: dict[tuple[str, str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in metadata["keys"]:
        kind = (
            "FOREIGN KEY"
            if row.get("referenced_table_name")
            else "PRIMARY KEY"
            if row["constraint_name"] == "PRIMARY"
            else "UNIQUE"
        )
        key_groups[(row["table_schema"], row["table_name"], kind, row["constraint_name"])].append(row)
    for (schema, name, kind, constraint), rows in key_groups.items():
        rows.sort(key=lambda row: int(row["ordinal_position"]))
        table = tables.get(_table_key(schema, name))
        if table is None:
            raise InvalidSchemaContext(f"Key refers to missing table: {schema}.{name}")
        columns = [row["column_name"] for row in rows]
        if kind == "PRIMARY KEY":
            if table["primary_key"]:
                raise InvalidSchemaContext(f"Duplicate primary key metadata: {schema}.{name}")
            table["primary_key"] = columns
        elif kind == "UNIQUE":
            table["unique_keys"].append({"name": constraint, "columns": columns})
        else:
            reference = reference_rules.get((schema, name, constraint), {})
            table["foreign_keys"].append(
                {
                    "name": constraint,
                    "columns": columns,
                    "referenced_schema": rows[0]["referenced_table_schema"],
                    "referenced_table": rows[0]["referenced_table_name"],
                    "referenced_columns": [row["referenced_column_name"] for row in rows],
                    "on_update": reference.get("update_rule"),
                    "on_delete": reference.get("delete_rule"),
                }
            )

    for row in metadata["checks"]:
        target(row)["checks"].append(
            {
                "name": row["constraint_name"],
                "expression": row["check_clause"],
                "enforced": row["enforced"] == "YES",
            }
        )

    index_groups: dict[tuple[str, str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in metadata["indexes"]:
        index_groups[(row["table_schema"], row["table_name"], row["index_name"])].append(row)
    for (schema, name, index_name), rows in index_groups.items():
        rows.sort(key=lambda row: int(row["seq_in_index"]))
        table = tables.get(_table_key(schema, name))
        if table is None:
            raise InvalidSchemaContext(f"Index refers to missing table: {schema}.{name}")
        table["indexes"].append(
            {
                "name": index_name,
                "unique": int(rows[0]["non_unique"]) == 0,
                "type": rows[0]["index_type"],
                "visible": rows[0].get("is_visible") == "YES",
                "parts": [
                    {
                        "column": row.get("column_name"),
                        "expression": row.get("expression"),
                        "prefix_length": int_or_none(row.get("sub_part")),
                        "order": row.get("collation"),
                    }
                    for row in rows
                ],
            }
        )

    for row in metadata["triggers"]:
        target(row)["triggers"].append(
            {
                key: row.get(key)
                for key in (
                    "trigger_name",
                    "event_manipulation",
                    "action_timing",
                    "action_order",
                    "action_statement",
                    "definer",
                    "sql_mode",
                    "character_set_client",
                    "collation_connection",
                )
            }
        )
    validate_schema_context(context)
    return context

def validate_schema_context(context: Mapping[str, Any]) -> None:
    """Validate the portable schema-context contract before it becomes evidence."""
    if not isinstance(context.get("tables"), dict):
        raise InvalidSchemaContext("tables must be an object")
    if not context["tables"]:
        raise InvalidSchemaContext("tables must not be empty")
    for key, table in context["tables"].items():
        if not isinstance(key, str) or not isinstance(table, dict):
            raise InvalidSchemaContext("Each table entry must have a string key and object value")
        required_table_fields = {
            "schema",
            "name",
            "kind",
            "columns",
            "column_order",
            "primary_key",
            "unique_keys",
            "foreign_keys",
            "checks",
            "indexes",
            "triggers",
        }
        missing_table_fields = required_table_fields - set(table)
        if missing_table_fields:
            raise InvalidSchemaContext(f"Table {key} is missing fields: {sorted(missing_table_fields)}")
        if not isinstance(table["schema"], str) or not isinstance(table["name"], str):
            raise InvalidSchemaContext(f"Table identity must be strings: {key}")
        for list_field in (
            "column_order",
            "primary_key",
            "unique_keys",
            "foreign_keys",
            "checks",
            "indexes",
            "triggers",
        ):
            if not isinstance(table[list_field], list):
                raise InvalidSchemaContext(f"Table field {list_field} must be a list: {key}")
        if key != _table_key(table.get("schema"), table.get("name")):
            raise InvalidSchemaContext(f"Table key does not match table identity: {key}")
        columns = table.get("columns")
        order = table.get("column_order")
        if not isinstance(columns, dict) or not isinstance(order, list):
            raise InvalidSchemaContext(f"Malformed columns for {key}")
        if not columns:
            raise InvalidSchemaContext(f"Table has no visible columns: {key}")
        required_column_fields = {
            "name",
            "ordinal",
            "data_type",
            "nullable",
            "auto_increment",
            "generated",
            "invisible",
        }
        for column_name, column in columns.items():
            if not isinstance(column_name, str) or not isinstance(column, dict):
                raise InvalidSchemaContext(f"Malformed column entry for {key}")
            missing_column_fields = required_column_fields - set(column)
            if missing_column_fields:
                raise InvalidSchemaContext(
                    f"Column {key}.{column_name} is missing fields: {sorted(missing_column_fields)}"
                )
            if column["name"] != column_name:
                raise InvalidSchemaContext(f"Column key does not match name: {key}.{column_name}")
            if (
                not isinstance(column["ordinal"], int)
                or isinstance(column["ordinal"], bool)
                or column["ordinal"] < 1
            ):
                raise InvalidSchemaContext(f"Invalid column ordinal: {key}.{column_name}")
        expected_order = [column["name"] for column in sorted(columns.values(), key=lambda column: column["ordinal"])]
        ordinals = [column["ordinal"] for column in columns.values()]
        if len(ordinals) != len(set(ordinals)):
            raise InvalidSchemaContext(f"Duplicate column ordinal for {key}")
        if order != expected_order:
            raise InvalidSchemaContext(f"column_order is not ordinal order for {key}")
        constraints: list[list[str]] = []
        for item in table["unique_keys"]:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                raise InvalidSchemaContext(f"Malformed unique key for {key}")
            constraints.append(item.get("columns"))
        for item in table["foreign_keys"]:
            if not isinstance(item, dict) or not isinstance(item.get("name"), str):
                raise InvalidSchemaContext(f"Malformed foreign key for {key}")
            constraints.append(item.get("columns"))
        if table.get("primary_key"):
            constraints.append(table["primary_key"])
        for key_columns in constraints:
            if (
                not isinstance(key_columns, list)
                or not key_columns
                or any(not isinstance(column, str) or column not in columns for column in key_columns)
            ):
                raise InvalidSchemaContext(f"Constraint has invalid local columns for {key}")
        for foreign_key in table.get("foreign_keys", []):
            referenced_columns = foreign_key.get("referenced_columns")
            if (
                not isinstance(referenced_columns, list)
                or len(foreign_key["columns"]) != len(referenced_columns)
                or any(not isinstance(column, str) for column in referenced_columns)
                or not isinstance(foreign_key.get("referenced_schema"), str)
                or not isinstance(foreign_key.get("referenced_table"), str)
            ):
                raise InvalidSchemaContext(f"Foreign-key arity mismatch for {key}")
        for index in table["indexes"]:
            if not isinstance(index, dict) or not isinstance(index.get("name"), str):
                raise InvalidSchemaContext(f"Malformed index for {key}")
            parts = index.get("parts")
            if not isinstance(parts, list) or not parts:
                raise InvalidSchemaContext(f"Index has no parts for {key}")
            for part in parts:
                if not isinstance(part, dict):
                    raise InvalidSchemaContext(f"Malformed index part for {key}")
                column, expression = part.get("column"), part.get("expression")
                if (column is None) == (expression is None):
                    raise InvalidSchemaContext(f"Index part must have one column or expression for {key}")
                if column is not None and (not isinstance(column, str) or column not in columns):
                    raise InvalidSchemaContext(f"Index refers to missing column for {key}")

_INTEGER_TYPES = frozenset(
    {
        "tinyint",
        "smallint",
        "mediumint",
        "int",
        "integer",
        "bigint",
    }
)
_DECIMAL_TYPES = frozenset({"decimal", "numeric", "dec", "fixed", "float", "double", "real"})
_STRING_TYPES = frozenset({"char", "varchar", "tinytext", "text", "mediumtext", "longtext"})
_TEMPORAL_TYPES = frozenset({"date", "time", "datetime", "timestamp", "year"})
_BINARY_TYPES = frozenset(
    {"binary", "varbinary", "tinyblob", "blob", "mediumblob", "longblob", "bit"}
)

def classify_mysql_type(*, data_type: str, column_type: str) -> str:
    """Map MySQL metadata into the small set of profile-domain families."""
    base = str(data_type or "").strip().lower()
    rendered = str(column_type or "").strip().lower()
    if base in {"bool", "boolean"} or (base == "tinyint" and re.search(r"\(\s*1\s*\)", rendered)):
        return "boolean"
    if base in _INTEGER_TYPES:
        return "integer"
    if base in _DECIMAL_TYPES:
        return "decimal"
    if base == "enum":
        return "enum"
    if base in _STRING_TYPES:
        return "string"
    if base in _TEMPORAL_TYPES:
        return "temporal"
    if base == "json":
        return "json"
    if base in _BINARY_TYPES:
        return "binary"
    return "unknown"

def _parse_mysql_enum_values(column_type: str) -> tuple[str, ...]:
    """Parse MySQL ENUM('a','b') metadata without treating it as SQL to execute."""
    rendered = str(column_type or "").strip()
    if not rendered.lower().startswith("enum(") or not rendered.endswith(")"):
        return ()
    body = rendered[5:-1]
    values: list[str] = []
    index = 0
    while index < len(body):
        while index < len(body) and body[index].isspace():
            index += 1
        if index >= len(body) or body[index] != "'":
            return ()
        index += 1
        value: list[str] = []
        while index < len(body):
            char = body[index]
            if char == "\\" and index + 1 < len(body):
                value.append(body[index + 1])
                index += 2
                continue
            if char == "'":
                if index + 1 < len(body) and body[index + 1] == "'":
                    value.append("'")
                    index += 2
                    continue
                index += 1
                break
            value.append(char)
            index += 1
        else:
            return ()
        values.append("".join(value))
        while index < len(body) and body[index].isspace():
            index += 1
        if index == len(body):
            break
        if body[index] != ",":
            return ()
        index += 1
    return tuple(values)

def column_constraints(
    column: Mapping[str, Any],
    table: Mapping[str, Any],
    schema_context: Mapping[str, Any],
) -> ColumnConstraints:
    """Convert one resolved column's metadata into planner-safe constraints."""
    del schema_context  # Reserved for future cross-table policy lookups.
    data_type = str(column.get("data_type") or "").lower()
    column_type = str(column.get("column_type") or "")
    family = classify_mysql_type(data_type=data_type, column_type=column_type)
    signed = None
    if family in {"integer", "decimal"}:
        signed = "unsigned" not in column_type.lower()

    foreign_key: ResolvedForeignKey | None = None
    column_name = str(column.get("name") or "")
    for item in table.get("foreign_keys", []):
        if not isinstance(item, Mapping):
            continue
        local_columns = item.get("columns")
        referenced_columns = item.get("referenced_columns")
        if not isinstance(local_columns, list) or not isinstance(referenced_columns, list):
            continue
        try:
            position = local_columns.index(column_name)
        except ValueError:
            continue
        if position >= len(referenced_columns):
            continue
        foreign_key = ResolvedForeignKey(
            schema=str(item.get("referenced_schema") or ""),
            table=str(item.get("referenced_table") or ""),
            column=str(referenced_columns[position] or ""),
        )
        break

    checks = tuple(
        str(item.get("expression"))
        for item in table.get("checks", [])
        if isinstance(item, Mapping) and item.get("expression") is not None
    )
    max_length = column.get("character_maximum_length")
    return ColumnConstraints(
        type_family=family,
        data_type=data_type,
        signed=signed,
        numeric_precision=column.get("numeric_precision")
        if isinstance(column.get("numeric_precision"), int)
        else None,
        numeric_scale=column.get("numeric_scale") if isinstance(column.get("numeric_scale"), int) else None,
        max_length=max_length if isinstance(max_length, int) else None,
        enum_values=_parse_mysql_enum_values(column_type) if family == "enum" else (),
        nullable=bool(column.get("nullable")),
        foreign_key=foreign_key,
        checks=checks,
    )

class SchemaAnalyzer:
    """Build one stable schema context from two matching metadata snapshots."""

    def __init__(self, connection: Any, database: str):
        self.connection = connection
        self.database = database

    def _snapshot(self, settings: dict[str, Any]) -> dict[str, Any]:
        metadata = {
            name: _query_rows(self.connection, sql, (self.database,))
            for name, sql in QUERIES.items()
        }
        context = build_schema_context(
            self.database,
            metadata,
            settings,
            datetime.now(timezone.utc).isoformat(),
        )
        context["fingerprint"] = schema_fingerprint(context)
        return context

    def collect(self, *, verify_stable: bool = True) -> dict[str, Any]:
        settings = read_server_settings(self.connection)
        first = self._snapshot(settings)
        if not verify_stable:
            first["consistency_check"] = "single_read"
            return first
        second = self._snapshot(settings)
        if first["fingerprint"] != second["fingerprint"]:
            raise SchemaChangedDuringCollection("DDL changed during collection")
        second["consistency_check"] = "two_matching_reads"
        return second


def load_schema_context(
    path: str | Path,
    *,
    expected_target: str,
    expected_database: str,
) -> dict[str, Any]:
    """Read and verify a published schema-context artifact."""
    try:
        context = read_json_object(path)
    except ArtifactStoreError as error:
        raise InvalidSchemaContext(f"Invalid JSON artifact: {error}") from error
    _require_schema_json(context)
    if (
        context.get("format_version") != 1
        or context.get("fingerprint_version") != 1
        or context.get("dbms") != "MySQL"
    ):
        raise InvalidSchemaContext("Unsupported schema context format")
    validate_schema_context(context)
    if context.get("target_id") != expected_target:
        raise InvalidSchemaContext("Artifact target_id does not match caller")
    if context.get("database") != expected_database:
        raise InvalidSchemaContext("Artifact database does not match caller")
    if context.get("fingerprint") != schema_fingerprint(context):
        raise InvalidSchemaContext("Artifact fingerprint does not match content")
    return context

class SchemaCollector:
    """Collect and publish baseline/instrument schema contexts for one target."""

    def __init__(
        self,
        database: DatabaseSettings,
        artifacts: ArtifactPaths,
        *,
        lock_timeout_seconds: float = 30.0,
    ):
        if lock_timeout_seconds <= 0:
            raise SchemaCollectionError("lock_timeout_seconds must be positive")
        self.database = database
        self.artifacts = artifacts
        self.lock_timeout_seconds = lock_timeout_seconds

    def _connect(self) -> Any:
        try:
            import pymysql
        except ImportError as error:  # pragma: no cover - exercised in container setup
            raise SchemaCollectionError("PyMySQL is required for schema collection") from error

        try:
            return pymysql.connect(
                host=self.database.host,
                port=self.database.port,
                user=self.database.user,
                password=self.database.password,
                database=self.database.database,
                connect_timeout=self.database.connect_timeout_seconds,
                read_timeout=self.database.connect_timeout_seconds,
                write_timeout=self.database.connect_timeout_seconds,
                autocommit=True,
                cursorclass=pymysql.cursors.DictCursor,
            )
        except Exception as error:
            raise SchemaCollectionError(
                "Could not connect to the schema database "
                f"{self.database.host}:{self.database.port}/{self.database.database}: {type(error).__name__}"
            ) from error

    def _load(self, path: Path) -> dict[str, Any]:
        try:
            return load_schema_context(
                path,
                expected_target=self.artifacts.target_id,
                expected_database=self.database.database,
            )
        except Exception as error:
            raise SchemaCollectionError(f"Invalid existing schema artifact {path}: {error}") from error

    @staticmethod
    def _publish(path: Path, context: dict[str, Any]) -> None:
        validate_schema_context(context)
        _require_schema_json(context)
        expected = schema_fingerprint(context)
        if context.get("fingerprint") != expected:
            raise InvalidSchemaContext("Refusing to publish a context with bad fingerprint")
        atomic_write_json(
            path,
            context,
            temporary_prefix=".schema-context-",
            sync_directory=True,
        )

    def _collect_and_publish(self, path: Path, *, reuse_existing: bool) -> dict[str, Any]:
        self.artifacts.target_root.mkdir(parents=True, exist_ok=True)
        with exclusive_process_lock(self.artifacts.lock, self.lock_timeout_seconds):
            if reuse_existing and path.exists():
                return self._load(path)

            with closing(self._connect()) as connection:
                try:
                    context = SchemaAnalyzer(connection, self.database.database).collect(verify_stable=True)
                except Exception as error:
                    raise SchemaCollectionError(
                        f"Could not collect stable metadata for {self.database.database}: "
                        f"{type(error).__name__}: {error}"
                    ) from error

            # target_id and capture time are operational metadata.  The
            # fingerprint intentionally represents schema shape only.
            context["target_id"] = self.artifacts.target_id
            context["fingerprint"] = schema_fingerprint(context)
            try:
                self._publish(path, context)
            except Exception as error:
                raise SchemaCollectionError(f"Could not publish schema artifact {path}: {error}") from error
            return context

    def collect_schema(self, *, reuse_existing: bool = True) -> dict[str, Any]:
        return self._collect_and_publish(self.artifacts.schema_file, reuse_existing=reuse_existing)

    def load_schema(self) -> dict[str, Any]:
        if not self.artifacts.schema_file.exists():
            raise SchemaCollectionError(
                f"Schema file does not exist: {self.artifacts.schema_file}. Run Phase 0 (baseline) first."
            )
        return self._load(self.artifacts.schema_file)