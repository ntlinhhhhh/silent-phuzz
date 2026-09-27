<?php
// overrides.d/08_mysqli_stmt.php

uopz_set_return('mysqli', 'prepare', function ($query) {
    if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
        return $this->prepare($query);
    }

    $stmt = $this->prepare($query);

    if ($stmt instanceof mysqli_stmt) {
        __phuzz_remember_stmt($stmt, $this, $query);
    }

    return $stmt;
}, true);

if (function_exists('mysqli_prepare')) {
    uopz_set_return('mysqli_prepare', function ($mysql, $query) {
        if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
            return mysqli_prepare($mysql, $query);
        }

        $stmt = mysqli_prepare($mysql, $query);

        if ($stmt instanceof mysqli_stmt) {
            __phuzz_remember_stmt($stmt, $mysql, $query);
        }

        return $stmt;
    }, true);
}

uopz_set_return('mysqli_stmt', 'bind_param', function ($types, &...$vars) {
    if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
        return $this->bind_param($types, ...$vars);
    }
    $result = $this->bind_param($types, ...$vars);
    if ($result) {
        __phuzz_remember_stmt_bound_references($this, $vars);
    }
    return $result;
}, true);

if (function_exists('mysqli_stmt_bind_param')) {
    uopz_set_return('mysqli_stmt_bind_param', function ($statement, $types, &...$vars) {
        if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
            return mysqli_stmt_bind_param($statement, $types, ...$vars);
        }
        $result = mysqli_stmt_bind_param($statement, $types, ...$vars);
        if ($result) {
            __phuzz_remember_stmt_bound_references($statement, $vars);
        }
        return $result;
    }, true);
}

function __phuzz_execute_mysqli_stmt($statement, $params, $function, callable $execute) {
    $query = __phuzz_resolve_sql_for_stmt($statement);
    $bind_params = $params !== null
        ? __phuzz_normalize_bind_params($params)
        : __phuzz_resolve_bind_params_for_stmt($statement);
    $event_seq = __phuzz_next_event_seq();
    $markers = __phuzz_build_markers(null, $query, $bind_params);
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
        $errno = ($the_exception) ? -1 : $statement->errno;
        $errstr = ($the_exception) ? $the_exception->getMessage() : $statement->error;
    } else {
        $errno = 0;
        $errstr = '';
    }

    $affected = ($result !== false) ? $statement->affected_rows : -1;
    __phuzz_write_query_event(
        $function,
        $event_seq,
        null,
        $query,
        $bind_params,
        $result !== false,
        $errno,
        $errstr,
        $affected,
        $duration_ms,
        $timestamp,
        $markers
    );

    if ($result === false) {
        __phuzz_write_mysql_error(
            $function,
            [$query ?? 'PREPARED_STMT'],
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

uopz_set_return('mysqli_stmt', 'execute', function ($params = null) {
    if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
        return $params !== null ? $this->execute($params) : $this->execute();
    }

    return __phuzz_execute_mysqli_stmt(
        $this,
        $params,
        'mysqli_stmt::execute',
        function () use ($params) {
            return $params !== null ? $this->execute($params) : $this->execute();
        }
    );
}, true);

if (function_exists('mysqli_stmt_execute')) {
    uopz_set_return('mysqli_stmt_execute', function ($statement, $params = null) {
        if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
            return $params !== null
                ? mysqli_stmt_execute($statement, $params)
                : mysqli_stmt_execute($statement);
        }

        return __phuzz_execute_mysqli_stmt(
            $statement,
            $params,
            'mysqli_stmt_execute',
            function () use ($statement, $params) {
                return $params !== null
                    ? mysqli_stmt_execute($statement, $params)
                    : mysqli_stmt_execute($statement);
            }
        );
    }, true);
}
