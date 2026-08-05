<?php
##########################################################################################
#                                     PDO overrides                                     #
##########################################################################################
uopz_set_return('PDO', 'prepare', function ($query, $options = []) {
    if (!$GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
        __phuzz_ensure_sensor_tables($this);
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
    __phuzz_ensure_sensor_tables($this);

    try {
        $result = $this->query(...$args);
        $the_exception = null;
    } catch (Throwable $e) {
        $result = false;
        $the_exception = $e;
    }

    $query = $args[0] ?? null;

    if ($result === false) {
        $errno = $the_exception ? -1 : $this->errorCode();
        $errstr = $the_exception ? $the_exception->getMessage() : $this->errorInfo();
        $json = json_encode([
            'function' => 'PDO::query',
            'params' => [$query],
            'errno' => $errno,
            'errstr' => $errstr,
        ]);
        __fuzzer_file_put_contents(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", $json . "\n", FILE_APPEND);
        chmod(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", 0777);
        if ($the_exception !== null) {
            throw $the_exception;
        }
    }

    $affected = ($result !== false) ? $result->rowCount() : -1;
    $json_event = json_encode([
        'function' => 'PDO::query',
        'params' => [$query],
        'result' => ($result !== false),
        'affected_rows' => $affected,
        'errno' => ($result === false) ? (($the_exception) ? -1 : $this->errorCode()) : 0,
        'errstr' => ($result === false) ? (($the_exception) ? $the_exception->getMessage() : $this->errorInfo()) : '',
    ]);
    __fuzzer_file_put_contents(__FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . ".json", $json_event . "\n", FILE_APPEND);
    chmod(__FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . ".json", 0777);

    return $result;
}, true);

uopz_set_return('PDO', 'exec', function ($statement) {
    if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
        return $this->exec($statement);
    }
    __phuzz_ensure_sensor_tables($this);

    try {
        $result = $this->exec($statement);
        $the_exception = null;
    } catch (Throwable $e) {
        $result = false;
        $the_exception = $e;
    }

    if ($result === false) {
        $errno = $the_exception ? -1 : $this->errorCode();
        $errstr = $the_exception ? $the_exception->getMessage() : $this->errorInfo();
        $json = json_encode([
            'function' => 'PDO::exec',
            'params' => [$statement],
            'errno' => $errno,
            'errstr' => $errstr,
        ]);
        __fuzzer_file_put_contents(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", $json . "\n", FILE_APPEND);
        chmod(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", 0777);
        if ($the_exception !== null) {
            throw $the_exception;
        }
    }

    $affected = ($result !== false) ? $result : -1;
    $json_event = json_encode([
        'function' => 'PDO::exec',
        'params' => [$statement],
        'result' => ($result !== false),
        'affected_rows' => $affected,
        'errno' => ($result === false) ? (($the_exception) ? -1 : $this->errorCode()) : 0,
        'errstr' => ($result === false) ? (($the_exception) ? $the_exception->getMessage() : $this->errorInfo()) : '',
    ]);
    __fuzzer_file_put_contents(__FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . ".json", $json_event . "\n", FILE_APPEND);
    chmod(__FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . ".json", 0777);

    return $result;
}, true);