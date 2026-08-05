<?php
##########################################################################################
#                              PDOStatement overrides                                    #
##########################################################################################

uopz_set_return(
    'PDOStatement',
    'execute',
    function ($params = null) {
        __phuzz_ensure_sensor_tables($this);
        try {
            $result = $this->execute($params);
            $the_exception = null;
        } catch(Throwable $e) {
            $result = false;
            $the_exception = $e;
        }

        $query = $this->queryString; // PDO tuyệt vời ở chỗ nó lưu lại câu SQL

        // 1. Lỗi
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

            if($the_exception != null) throw $the_exception;
        }

        // 2. Unconditional
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
    },
    true
);
?>