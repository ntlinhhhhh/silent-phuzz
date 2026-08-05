<?php
// overrides.d/00_init_sensor_tables.php (Core Helper Library)

if (!isset($GLOBALS['__PHUZZ_SUPPRESS_HOOKS'])) {
    $GLOBALS['__PHUZZ_SUPPRESS_HOOKS'] = false;
}

// thực hiện khóa hook để tránh vòng lặp vô hạn khi gọi các hàm PDO hoặc mysqli bên trong các hàm này
function __phuzz_run_unhooked(callable $fn) {
    $prev = $GLOBALS['__PHUZZ_SUPPRESS_HOOKS'];
    $GLOBALS['__PHUZZ_SUPPRESS_HOOKS'] = true;
    try {
        return $fn();
    } finally {
        $GLOBALS['__PHUZZ_SUPPRESS_HOOKS'] = $prev;
    }
}

// tạo một WeakMap để lưu trữ thông tin về các prepared statement và kết nối cơ sở dữ liệu tương ứng
if (!isset($GLOBALS['__PHUZZ_STMT_MAP'])) {
    $GLOBALS['__PHUZZ_STMT_MAP'] = new WeakMap();
}

function __phuzz_remember_stmt($stmt, $connection, string $sql): void {
    if ($stmt instanceof mysqli_stmt || $stmt instanceof PDOStatement) {
        $GLOBALS['__PHUZZ_STMT_MAP'][$stmt] = ['conn' => $connection, 'sql' => $sql];
    }
}

function __phuzz_resolve_connection_for_stmt($stmt) {
    return $GLOBALS['__PHUZZ_STMT_MAP'][$stmt]['conn'] ?? null;
}

function __phuzz_resolve_sql_for_stmt($stmt): ?string {
    return $GLOBALS['__PHUZZ_STMT_MAP'][$stmt]['sql'] ?? null;
}

function __phuzz_ensure_sensor_tables($db_link_or_pdo) {
    static $initialized_contexts = [];

    if ($db_link_or_pdo instanceof PDOStatement || $db_link_or_pdo instanceof mysqli_stmt) {
        return;
    }
    if (!is_object($db_link_or_pdo)) {
        return;
    }

    __phuzz_run_unhooked(function () use ($db_link_or_pdo, &$initialized_contexts) {
        $current_db = null;

        try {
            if ($db_link_or_pdo instanceof mysqli) {
                if (@mysqli_real_query($db_link_or_pdo, "SELECT DATABASE()")) {
                    $res = @mysqli_store_result($db_link_or_pdo);
                    if ($res) {
                        if ($row = mysqli_fetch_row($res)) {
                            $current_db = $row[0];
                        }
                        mysqli_free_result($res);
                    }
                }
            } elseif ($db_link_or_pdo instanceof PDO) {
                $stmt = @$db_link_or_pdo->query("SELECT DATABASE()");
                if ($stmt && $row = $stmt->fetch(PDO::FETCH_NUM)) {
                    $current_db = $row[0];
                }
            }
        } catch (Throwable $e) {
            return;
        }

        if (empty($current_db)) {
            return;
        }

        $context_key = spl_object_id($db_link_or_pdo) . '_' . $current_db;
        if (isset($initialized_contexts[$context_key])) {
            return;
        }

        $sql = "
            CREATE TABLE IF NOT EXISTS __phuzz_insert (
                id INT AUTO_INCREMENT PRIMARY KEY,
                marker VARCHAR(100) NOT NULL
            ) ENGINE=InnoDB;

            CREATE TABLE IF NOT EXISTS __phuzz_update (
                id INT AUTO_INCREMENT PRIMARY KEY,
                marker VARCHAR(100) NOT NULL
            ) ENGINE=InnoDB;
            INSERT IGNORE INTO __phuzz_update (id, marker) VALUES (1, 'marker');

            CREATE TABLE IF NOT EXISTS __phuzz_delete (
                id INT AUTO_INCREMENT PRIMARY KEY,
                marker VARCHAR(100) NOT NULL
            ) ENGINE=InnoDB;
            INSERT IGNORE INTO __phuzz_delete (id, marker) VALUES (1, 'marker');

            CREATE TABLE IF NOT EXISTS __phuzz_history (
                pz_trace_id VARCHAR(100) NOT NULL PRIMARY KEY,
                url TEXT,
                method VARCHAR(10),
                request_data TEXT
            ) ENGINE=InnoDB;
        ";

        try {
            if ($db_link_or_pdo instanceof mysqli) {
                if (@$db_link_or_pdo->multi_query($sql)) {
                    do {
                        if ($res = @$db_link_or_pdo->store_result()) {
                            $res->free();
                        }
                    } while (@$db_link_or_pdo->more_results() && @$db_link_or_pdo->next_result());
                }
            } elseif ($db_link_or_pdo instanceof PDO) {
                foreach (array_filter(array_map('trim', explode(';', $sql))) as $stmt) {
                    @$db_link_or_pdo->exec($stmt);
                }
            }
        } catch (Throwable $e) {
            error_log("[Phuzz Init Error] Failed to create sensor tables: " . $e->getMessage());
        }

        $initialized_contexts[$context_key] = true;
    });
}