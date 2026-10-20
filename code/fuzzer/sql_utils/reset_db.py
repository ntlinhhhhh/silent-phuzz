"""Database fixture reset module for Silent PHUZZ.

Responsibilities:
- Restore target database fixture to a clean, immutable state between phases.
- Safely parse commands via shlex.split (avoiding shell=True to prevent command injection).
- Inject standardized lifecycle environment variables (PHUZZ_LIFECYCLE_STEP, PHUZZ_RESET_TIME).
- Provide execution timeout protection against hanging database commands.
"""
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shlex
import subprocess
import time
from typing import Mapping
from sql_utils.schema_context import DatabaseSettings

class DatabaseResetError(RuntimeError):
    pass

class ResetConfigurationError(DatabaseResetError):
    pass

class ResetExecutionError(DatabaseResetError):
    pass

@dataclass(frozen=True)
class ResetCommand:
    """Safe command execution wrapper without invoking an intermediate shell."""

    argv: tuple[str, ...]

    @classmethod
    def from_text(cls, value: str | None) -> ResetCommand | None:
        """Parse a command string into safe argv tokens using shlex.split()."""
        if value is None or not value.strip():
            return None
        try:
            tokens = tuple(shlex.split(value))
        except ValueError as error:
            raise ResetConfigurationError(f"Invalid database reset command syntax: {error}") from error
        if not tokens:
            raise ResetConfigurationError("Database reset command is empty")
        return cls(tokens)

    def run(
        self,
        *,
        cwd: str | Path | None = None,
        environ: Mapping[str, str] | None = None,
        timeout_seconds: float = 60.0,
    ) -> None:
        """Execute the reset command as a safe subprocess with timeout protection."""
        child_env = os.environ.copy()
        if environ:
            child_env.update(environ)

        child_env["PHUZZ_LIFECYCLE_STEP"] = "reset"
        child_env["PHUZZ_RESET_TIME"] = str(int(time.time()))

        working_dir = None if cwd is None else str(Path(cwd).resolve())

        try:
            completed = subprocess.run(
                self.argv,
                cwd=working_dir,
                env=child_env,
                check=False,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as error:
            raise ResetExecutionError(
                f"Timed out ({timeout_seconds}s) executing reset command: {self.argv[0]!r}"
            ) from error
        except OSError as error:
            raise ResetExecutionError(
                f"Failed to start reset command {self.argv[0]!r}: {error}"
            ) from error

        if completed.returncode != 0:
            raise ResetExecutionError(
                f"Database reset command failed with exit code: {completed.returncode}"
            )


class DatabaseResetter:
    """Manages the target database reset lifecycle."""

    def __init__(
        self,
        command: ResetCommand | None = None,
        *,
        database: DatabaseSettings | None = None,
        snapshot_file: Path | None = None,
        cwd: str | Path | None = None,
    ):
        self.command = command
        self.database = database
        self.snapshot_file = snapshot_file
        self.cwd = cwd

    def snapshot(self, timeout_seconds: float = 60.0) -> None:
        """Phase 0: Tự động chụp lại Database sạch ban đầu bằng mysqldump."""
        if self.database is None or self.snapshot_file is None:
            print("[-] Warning: Database settings or snapshot_file is None, skipping snapshot.")
            return

        self.snapshot_file.parent.mkdir(parents=True, exist_ok=True)
        db = self.database

        cmd = ["mysqldump", f"--host={db.host}", f"--port={db.port}", f"--user={db.user}"]
        if db.password:
            cmd.append(f"--password={db.password}")
        cmd.append(db.database)

        print(f"[+] Taking initial database snapshot to: {self.snapshot_file} ...")
        try:
            with open(self.snapshot_file, "wb") as f:
                completed = subprocess.run(cmd, stdout=f, stderr=subprocess.PIPE, timeout=timeout_seconds)
                if completed.returncode != 0:
                    err = completed.stderr.decode(errors="ignore")
                    print(f"[-] mysqldump error: {err.strip()}")
                else:
                    print(f"[+] Snapshot successfully created! Size: {self.snapshot_file.stat().st_size} bytes")
        except FileNotFoundError:
            print("[-] Error: 'mysqldump' command not found inside this container! Please install default-mysql-client.")
        except Exception as e:
            print(f"[-] Snapshot failed with exception: {e}")

    def reset(self, timeout_seconds: float = 60.0) -> None:
        """Phase 2: Tự động khôi phục lại Database từ file snapshot."""
        if self.command is not None:
            self.command.run(cwd=self.cwd, timeout_seconds=timeout_seconds)
            return

        if self.snapshot_file is not None and self.snapshot_file.exists() and self.database is not None:
            db = self.database
            
            # Cấu hình lệnh kết nối cơ sở
            cmd_base = ["mysql", f"--host={db.host}", f"--port={db.port}", f"--user={db.user}"]
            if db.password:
                cmd_base.append(f"--password={db.password}")

            print(f"[+] Resetting database `{db.database}` to initial snapshot state...")

            try:
                # BƯỚC 1: xóa db hiện tại
                drop_create_sql = f"DROP DATABASE IF EXISTS `{db.database}`; CREATE DATABASE `{db.database}`;"
                wipe_cmd = cmd_base + ["-e", drop_create_sql]
                
                wipe_res = subprocess.run(wipe_cmd, stderr=subprocess.PIPE, timeout=timeout_seconds)
                if wipe_res.returncode != 0:
                    err = wipe_res.stderr.decode(errors="ignore")
                    raise ResetExecutionError(f"Failed to drop/recreate database: {err}")

                # BƯỚC 2: nạp file snapshot.sql
                restore_cmd = cmd_base + [db.database]
                with open(self.snapshot_file, "rb") as f:
                    completed = subprocess.run(restore_cmd, stdin=f, stderr=subprocess.PIPE, timeout=timeout_seconds)
                    if completed.returncode != 0:
                        err = completed.stderr.decode(errors="ignore")
                        raise ResetExecutionError(f"Auto-restore from snapshot failed: {err}")

                print(f"[+] Database `{db.database}` has been completely restored and cleaned!")
                return

            except Exception as error:
                raise ResetExecutionError(f"Failed to reset database from {self.snapshot_file}: {error}") from error

        raise ResetConfigurationError(
            "No reset mechanism available. Please provide --reset-command or ensure snapshot_file exists."
        )

def parse_reset_command(value: str | None) -> ResetCommand | None:
    """Convenience helper to parse a CLI text command into a ResetCommand."""
    return ResetCommand.from_text(value)