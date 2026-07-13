import mysql.connector
import os

class DBResetAdapter:
    def __init__(self, db_config=None):
        self.config = db_config or {
            'host': os.environ.get('DB_HOST', 'db'),
            'database': os.environ.get('DB_DATABASE', os.environ.get('MYSQL_DATABASE', 'db')),
            'user': os.environ.get('DB_USER', os.environ.get('MYSQL_USER', 'user')),
            'password': os.environ.get('DB_PASSWORD', os.environ.get('MYSQL_PASSWORD', 'password'))
        }

    def reset_dml_state(self):
        """Reset sensor tables and honey columns to baseline clean state."""
        pass

    def reset_ddl_state(self):
        """Clean up structural changes (e.g. drop temporary tables)."""
        pass


class MySQLResetAdapter(DBResetAdapter):
    def __init__(self, db_config=None):
        super().__init__(db_config)
        # Khai báo rỗng mặc định, giá trị sẽ được load động từ file config JSON của fuzzer
        self.second_order_tables = []

    def reset_dml_state(self):
        try:
            conn = mysql.connector.connect(**self.config)
            cursor = conn.cursor()
            
            # Reset các bảng sensor của PHUZZ
            sensor_tables = ["__phuzz_sensor_insert", "__phuzz_sensor_update", "__phuzz_sensor_delete"]
            for table in sensor_tables:
                try:
                    cursor.execute(f"TRUNCATE TABLE `{table}`")
                except Exception:
                    pass

            # Reset honey columns back to default/empty values if modified (Canary check)
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
                    
            # Phương án C: Restore DB từ file SQL backup / seed
            init_sql_path = self.config.get('init_db_sql', './resources/init_db.sql')
            if os.path.exists(init_sql_path):
                try:
                    with open(init_sql_path, 'r', encoding='utf-8') as f:
                        sql_content = f.read()
                    # Tách các câu lệnh qua dấu chấm phẩy
                    statements = sql_content.split(';')
                    for statement in statements:
                        statement = statement.strip()
                        if not statement:
                            continue
                        # Bỏ các dòng comment
                        lines = [line for line in statement.split('\n') if not (line.strip().startswith('--') or line.strip().startswith('#'))]
                        stmt_cleaned = '\n'.join(lines).strip()
                        if stmt_cleaned:
                            cursor.execute(stmt_cleaned)
                except Exception as e:
                    print(f"Error restoring DB backup: {e}")
            else:
                # Nếu không có file SQL backup, sử dụng phương án xóa bản ghi truyền thống
                for table in self.second_order_tables:
                    try:
                        cursor.execute(f"DELETE FROM `{table}` WHERE 1=1")
                    except Exception:
                        pass
            
            # Truncate fuzz_history table to clean up history logs between runs
            try:
                cursor.execute("TRUNCATE TABLE `fuzz_history`")
            except Exception:
                pass

            conn.commit()
            cursor.close()
            conn.close()
        except Exception:
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
