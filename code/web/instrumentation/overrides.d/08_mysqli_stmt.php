<?php
// overrides.d/08_mysqli_stmt.php

uopz_set_return('mysqli', 'prepare', function ($query) {
    if (!$GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
        __phuzz_ensure_sensor_tables($this);
    }
    $stmt = $this->prepare($query);
    if ($stmt instanceof mysqli_stmt) {
        __phuzz_remember_stmt($stmt, $this, $query);
    }
    return $stmt;
}, true);

if (function_exists('mysqli_prepare')) {
    uopz_set_return('mysqli_prepare', function ($mysql, $query) {
        if (!$GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
            __phuzz_ensure_sensor_tables($mysql);
        }
        $stmt = mysqli_prepare($mysql, $query);
        if ($stmt instanceof mysqli_stmt) {
            __phuzz_remember_stmt($stmt, $mysql, $query);
        }
        return $stmt;
    }, true);
}

uopz_set_return('mysqli_stmt', 'execute', function ($params = null) {
    if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
        return $params !== null ? $this->execute($params) : $this->execute();
    }

    try {
        if ($params !== null) {
            $result = $this->execute($params);
        } else {
            $result = $this->execute();
        }
        $the_exception = null;
    } catch (Throwable $e) {
        $result = false;
        $the_exception = $e;
    }

    $query = __phuzz_resolve_sql_for_stmt($this) ?? 'PREPARED_STMT';

    if ($result === false) {
        $errno = ($the_exception) ? -1 : $this->errno;
        $errstr = ($the_exception) ? $the_exception->getMessage() : $this->error;
        $json = json_encode([
            'function' => 'mysqli_stmt::execute',
            'params' => [$query],
            'errno' => $errno,
            'errstr' => $errstr,
        ]);
        __fuzzer_file_put_contents(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", $json . "\n", FILE_APPEND);
        chmod(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", 0777);
        if ($the_exception != null) {
            throw $the_exception;
        }
    }

    $affected = ($result !== false) ? $this->affected_rows : -1;
    $json_event = json_encode([
        'function' => 'mysqli_stmt::execute',
        'params' => [$query],
        'result' => ($result !== false),
        'affected_rows' => $affected,
        'errno' => ($result === false) ? (($the_exception) ? -1 : $this->errno) : 0,
        'errstr' => ($result === false) ? (($the_exception) ? $the_exception->getMessage() : $this->error) : '',
    ]);
    __fuzzer_file_put_contents(__FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . ".json", $json_event . "\n", FILE_APPEND);
    chmod(__FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . ".json", 0777);

    return $result;
}, true);