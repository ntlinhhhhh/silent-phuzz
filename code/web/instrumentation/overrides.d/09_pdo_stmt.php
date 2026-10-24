<?php
// overrides.d/09_pdo_stmt.php

uopz_set_return('PDOStatement', 'bindValue', function ($parameter, $value, $type = PDO::PARAM_STR) {
    if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
        return $this->bindValue($parameter, $value, $type);
    }
    $result = $this->bindValue($parameter, $value, $type);
    if ($result) {
        __phuzz_remember_stmt_bound_value($this, $parameter, $value);
    }
    return $result;
}, true);

uopz_set_return('PDOStatement', 'bindParam', function (
    $parameter,
    &$variable,
    $type = PDO::PARAM_STR,
    $max_length = 0,
    $driver_options = null
) {
    if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
        return $this->bindParam($parameter, $variable, $type, $max_length, $driver_options);
    }
    $result = $this->bindParam($parameter, $variable, $type, $max_length, $driver_options);
    if ($result) {
        __phuzz_remember_stmt_bound_reference($this, $parameter, $variable);
    }
    return $result;
}, true);

uopz_set_return('PDOStatement', 'execute', function ($params = null) {
    if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
        return $params !== null ? $this->execute($params) : $this->execute();
    }

    $query = $this->queryString ?: __phuzz_resolve_sql_for_stmt($this);
    $bind_params = $params !== null
        ? __phuzz_normalize_bind_params($params)
        : __phuzz_resolve_bind_params_for_stmt($this);
    $event_seq = __phuzz_next_event_seq();
    $markers = __phuzz_build_fuzz_markers(null, $query, $bind_params);
    $started_at = __phuzz_timer_start();
    try {
        $result = $params !== null ? $this->execute($params) : $this->execute();
        $the_exception = null;
    } catch (Throwable $e) {
        $result = false;
        $the_exception = $e;
    }
    $duration_ms = __phuzz_duration_ms($started_at);
    $timestamp = __phuzz_utc_timestamp();

    if ($result === false) {
        $errno = ($the_exception) ? -1 : $this->errorCode();
        $errstr = ($the_exception) ? $the_exception->getMessage() : $this->errorInfo();
        __phuzz_write_mysql_error(
            'PDOStatement::execute',
            [$query ?? 'PDO_STATEMENT'],
            $errno,
            $errstr,
            $event_seq,
            $markers
        );
        if ($the_exception !== null) {
            throw $the_exception;
        }
    } else {
        $affected = $this->rowCount();
        __phuzz_write_query_success(
            'PDOStatement::execute',
            $event_seq,
            null,
            $query,
            $bind_params,
            $affected,
            $duration_ms,
            $timestamp,
            $markers
        );
    }

    return $result;
}, true);
