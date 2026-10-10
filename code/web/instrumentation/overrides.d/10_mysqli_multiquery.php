<?php
// overrides.d/10_mysqli_multiquery.php
// Capture one raw SQL batch for each MySQLi multi_query API invocation.

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

    try {
        $result = $execute();
        $the_exception = null;
    } catch (Throwable $e) {
        $result = false;
        $the_exception = $e;
    }

    $duration_ms = __phuzz_duration_ms($started_at);
    $timestamp = __phuzz_utc_timestamp();

    if ($result === false) {
        $errno = $the_exception ? -1 : $connection->errno;
        $errstr = $the_exception ? $the_exception->getMessage() : $connection->error;
    } else {
        $errno = 0;
        $errstr = '';
    }

    __phuzz_write_multi_query_event(
        $function,
        $event_seq,
        $sql,
        $mysql_connection_id,
        $result !== false,
        $errno,
        $errstr,
        $duration_ms,
        $timestamp,
        $markers
    );

    if ($result === false) {
        __phuzz_write_mysql_error(
            $function,
            [$sql],
            $errno,
            $errstr,
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
