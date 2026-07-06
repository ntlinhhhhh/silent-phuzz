import mysql.connector

class DBResetAdapter:
    def __init__(self, db_config=None):
        self.config = db_config or {
            'host': 'db',
            'database': 'silent_phuzz_db',
            'user': 'phuzz_user',
            'password': 'phuzz_password'
        }

    def reset_dml_state(self):
        """Reset sensor tables and honey columns to baseline clean state."""
        pass

    def reset_ddl_state(self):
        """Clean up structural changes (e.g. drop temporary tables)."""
        pass


class MySQLResetAdapter(DBResetAdapter):
    def reset_dml_state(self):
        try:
            conn = mysql.connector.connect(**self.config)
            cursor = conn.cursor()
            # Truncate fuzzer sensor tables if they exist
            sensor_tables = ["__phuzz_sensor_insert", "__phuzz_sensor_update", "__phuzz_sensor_delete"]
            for table in sensor_tables:
                try:
                    cursor.execute(f"TRUNCATE TABLE `{table}`")
                except Exception:
                    # Ignore if tables do not exist in the current target application
                    pass
            # Reset honey columns back to default/empty values if modified
            try:
                # Get tables that contain a 'canary' column and reset them
                cursor.execute(
                    "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.COLUMNS "
                    "WHERE COLUMN_NAME IN ('phuzz_canary', 'canary') AND TABLE_SCHEMA = %s",
                    (self.config['database'],)
                )
                tables_with_canary = [row[0] for row in cursor.fetchall()]
                for table in tables_with_canary:
                    cursor.execute(f"UPDATE `{table}` SET `canary` = 'safe'")
            except Exception:
                pass
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            # Silently ignore if DB connection fails
            pass

    def reset_ddl_state(self):
        try:
            conn = mysql.connector.connect(**self.config)
            cursor = conn.cursor()
            # Find and drop any temporary fuzz tables (prefix '__phuzz_tmp_')
            try:
                cursor.execute("SHOW TABLES LIKE '__phuzz_tmp_%'")
                tables = [row[0] for row in cursor.fetchall()]
                for table in tables:
                    cursor.execute(f"DROP TABLE `{table}`")
            except Exception:
                pass
            conn.commit()
            cursor.close()
            conn.close()
        except Exception as e:
            # Silently ignore if DB connection fails
            pass


class PostgresResetAdapter(DBResetAdapter):
    # Placeholders for Postgres
    def reset_dml_state(self):
        pass

    def reset_ddl_state(self):
        pass


class SQLiteResetAdapter(DBResetAdapter):
    # Placeholders for SQLite (experimental)
    def reset_dml_state(self):
        pass

    def reset_ddl_state(self):
        pass
