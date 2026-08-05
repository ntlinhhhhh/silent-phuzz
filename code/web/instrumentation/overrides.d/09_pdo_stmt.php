<?php
// overrides.d/09_pdo_stmt.php

uopz_set_return('PDOStatement', 'execute', function ($params = null) {
    if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
        return $params !== null ? $this->execute($params) : $this->execute();
    }

    try {
        $result = $this->execute($params);
        $the_exception = null;
    } catch (Throwable $e) {
        $result = false;
        $the_exception = $e;
    }

    $query = $this->queryString ?? (__phuzz_resolve_sql_for_stmt($this) ?? 'PDO_STATEMENT');

    if ($result === false) {
        $errno = ($the_exception) ? -1 : $this->errorCode();
        $errstr = ($the_exception) ? $the_exception->getMessage() : $this->errorInfo();
        $json = json_encode([
            'function' => 'PDOStatement::execute',
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

    $affected = ($result !== false) ? $this->rowCount() : -1;
    $json_event = json_encode([
        'function' => 'PDOStatement::execute',
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