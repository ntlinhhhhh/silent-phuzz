<?php
##########################################################################################
#                                     PDO overrides                                     #
##########################################################################################
uopz_set_return('PDO', 'prepare', function ($query, $options = []) {
    if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
        return $this->prepare($query, $options);
    }

    $stmt = $this->prepare($query, $options);

    if ($stmt instanceof PDOStatement) {
        __phuzz_remember_stmt($stmt, $this, $query);
    }

    return $stmt;
}, true);

uopz_set_return('PDO', 'query', function (...$args) {
    if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
        return $this->query(...$args);
    }

    $query = $args[0] ?? null;
    $event_seq = __phuzz_next_event_seq();
    $markers = __phuzz_build_fuzz_markers($query, null, null);
    $started_at = __phuzz_timer_start();
    try {
        $result = $this->query(...$args);
        $the_exception = null;
    } catch (Throwable $e) {
        $result = false;
        $the_exception = $e;
    }
    $duration_ms = __phuzz_duration_ms($started_at);
    $timestamp = __phuzz_utc_timestamp();

    if ($result === false) {
        $errno = $the_exception ? -1 : $this->errorCode();
        $errstr = $the_exception ? $the_exception->getMessage() : $this->errorInfo();
    } else {
        $errno = 0;
        $errstr = '';
    }

    if ($result instanceof PDOStatement) {
        __phuzz_remember_stmt($result, $this, $query);
    }

    $affected = ($result !== false) ? $result->rowCount() : -1;
    __phuzz_write_query_event(
        'PDO::query',
        $event_seq,
        $query,
        null,
        null,
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
            'PDO::query',
            [$query],
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
}, true);

uopz_set_return('PDO', 'exec', function ($statement) {
    if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
        return $this->exec($statement);
    }

    $event_seq = __phuzz_next_event_seq();
    $markers = __phuzz_build_fuzz_markers($statement, null, null);
    $started_at = __phuzz_timer_start();
    try {
        $result = $this->exec($statement);
        $the_exception = null;
    } catch (Throwable $e) {
        $result = false;
        $the_exception = $e;
    }
    $duration_ms = __phuzz_duration_ms($started_at);
    $timestamp = __phuzz_utc_timestamp();

    if ($result === false) {
        $errno = $the_exception ? -1 : $this->errorCode();
        $errstr = $the_exception ? $the_exception->getMessage() : $this->errorInfo();
    } else {
        $errno = 0;
        $errstr = '';
    }

    $affected = ($result !== false) ? $result : -1;
    __phuzz_write_query_event(
        'PDO::exec',
        $event_seq,
        $statement,
        null,
        null,
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
            'PDO::exec',
            [$statement],
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
}, true);