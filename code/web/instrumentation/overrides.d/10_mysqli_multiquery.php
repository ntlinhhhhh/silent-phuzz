<?php
// overrides.d/10_mysqli_multiquery.php

function __phuzz_get_performance_schema_connection() {
    static $ps_conn = null;
    if ($ps_conn === null || !@$ps_conn->ping()) {
        $host = getenv('SCHEMA_DB_HOST') ?: 'db';
        $user = getenv('SCHEMA_DB_USER') ?: 'user';
        $pass = getenv('SCHEMA_DB_PASSWORD') ?: 'password';
        $ps_conn = @new mysqli($host, $user, $pass, 'performance_schema');
    }
    return $ps_conn;
}

function __phuzz_collect_statements_from_performance_schema(
    $mysql_connection_id,
    $baseline_event_id
) {
    $statements = [];
    $has_error = false;
    $first_error_no = 0;
    $first_error_str = '';

    $ps_conn = __phuzz_get_performance_schema_connection();
    if (!$ps_conn || $ps_conn->connect_error) {
        return [$statements, false, 0, ''];
    }

    $query = "SELECT EVENT_ID, SQL_TEXT, MYSQL_ERRNO, MESSAGE_TEXT 
              FROM performance_schema.events_statements_history 
              WHERE THREAD_ID = (
                  SELECT THREAD_ID FROM performance_schema.threads 
                  WHERE PROCESSLIST_ID = " . (int)$mysql_connection_id . "
              )
              AND EVENT_ID > " . (int)$baseline_event_id . "
              ORDER BY EVENT_ID ASC";

    $prev_suppress = $GLOBALS['__PHUZZ_SUPPRESS_HOOKS'] ?? false;
    $GLOBALS['__PHUZZ_SUPPRESS_HOOKS'] = true;
    try {
        $ps_res = @$ps_conn->query($query);
        if ($ps_res) {
            while ($row = $ps_res->fetch_assoc()) {
                $errno = (int)$row['MYSQL_ERRNO'];
                $is_err = ($errno !== 0);
                if ($is_err && !$has_error) {
                    $has_error = true;
                    $first_error_no = $errno;
                    $first_error_str = (string)$row['MESSAGE_TEXT'];
                }
                $statements[] = [
                    'event_id' => (int)$row['EVENT_ID'],
                    'sql'      => $row['SQL_TEXT'],
                    'errno'    => $errno,
                    'error'    => $row['MESSAGE_TEXT'],
                    'success'  => !$is_err,
                ];
            }
            $ps_res->free();
        }
    } finally {
        $GLOBALS['__PHUZZ_SUPPRESS_HOOKS'] = $prev_suppress;
    }

    return [$statements, $has_error, $first_error_no, $first_error_str];
}

function __phuzz_execute_mysqli_multi_query(
    mysqli $connection,
    string $sql,
    string $function,
    callable $execute
) {
    $event_seq = __phuzz_next_event_seq();
    $markers = __phuzz_build_fuzz_markers($sql, null, null);
    $mysql_connection_id = $connection->thread_id;
    $started_at = __phuzz_timer_start();

    // 1. Lấy mốc EVENT_ID trước khi chạy multi_query qua kết nối phụ
    $baseline_event_id = 0;
    $ps_conn = __phuzz_get_performance_schema_connection();
    if ($ps_conn && !$ps_conn->connect_error) {
        $prev_suppress = $GLOBALS['__PHUZZ_SUPPRESS_HOOKS'] ?? false;
        $GLOBALS['__PHUZZ_SUPPRESS_HOOKS'] = true;
        try {
            $pre = @$ps_conn->query(
                "SELECT COALESCE(MAX(EVENT_ID), 0) AS max_id 
                 FROM performance_schema.events_statements_history 
                 WHERE THREAD_ID = (
                     SELECT THREAD_ID FROM performance_schema.threads 
                     WHERE PROCESSLIST_ID = " . (int)$mysql_connection_id . "
                 )"
            );
            if ($pre) {
                $row = $pre->fetch_assoc();
                $baseline_event_id = (int)$row['max_id'];
                $pre->free();
            }
        } finally {
            $GLOBALS['__PHUZZ_SUPPRESS_HOOKS'] = $prev_suppress;
        }
    }

    // 2. Chạy multi_query thực tế trên kết nối ứng dụng
    try {
        $result = $execute();
        $the_exception = null;
    } catch (Throwable $e) {
        $result = false;
        $the_exception = $e;
    }

    $duration_ms = __phuzz_duration_ms($started_at);
    $timestamp = __phuzz_utc_timestamp();

    // 3. Đọc kết quả các statement qua kết nối phụ
    list($statements, $ps_has_error, $ps_errno, $ps_errstr) = 
        __phuzz_collect_statements_from_performance_schema(
            $mysql_connection_id,
            $baseline_event_id
        );

    // Xác định lỗi tổng thể
    $has_error = ($result === false) || $ps_has_error || ($the_exception !== null);
    $final_errno = 0;
    $final_errstr = '';

    if ($has_error) {
        if ($the_exception !== null) {
            $final_errno = -1;
            $final_errstr = $the_exception->getMessage();
        } elseif ($ps_has_error) {
            $final_errno = $ps_errno;
            $final_errstr = $ps_errstr;
        } else {
            $final_errno = $connection->errno;
            $final_errstr = $connection->error;
        }
    }

    // 4. LUÔN ghi event vào query event log
    __phuzz_write_multi_query_event(
        $function,
        $event_seq,
        $sql,
        $mysql_connection_id,
        !$has_error,
        $final_errno,
        $final_errstr,
        $duration_ms,
        $timestamp,
        $markers,
        $statements
    );

    // 5. Nếu có lỗi, GHI THÊM vào mysql error log
    if ($has_error) {
        __phuzz_write_mysql_error(
            $function,
            [$sql],
            $final_errno,
            $final_errstr,
            $event_seq,
            $markers
        );

        if ($the_exception !== null) {
            throw $the_exception;
        }
    }

    return $result;
}

uopz_set_return('mysqli', 'multi_query', function ($sql) {
    if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
        return $this->multi_query($sql);
    }

    return __phuzz_execute_mysqli_multi_query(
        $this,
        $sql,
        'mysqli::multi_query',
        function () use ($sql) {
            return $this->multi_query($sql);
        }
    );
}, true);

if (function_exists('mysqli_multi_query')) {
    uopz_set_return('mysqli_multi_query', function ($connection, $sql) {
        if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
            return mysqli_multi_query($connection, $sql);
        }

        return __phuzz_execute_mysqli_multi_query(
            $connection,
            $sql,
            'mysqli_multi_query',
            function () use ($connection, $sql) {
                return mysqli_multi_query($connection, $sql);
            }
        );
    }, true);
}
