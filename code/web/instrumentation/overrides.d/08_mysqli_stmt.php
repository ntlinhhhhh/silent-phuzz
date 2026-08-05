<?php
##########################################################################################
#                              mysqli_stmt overrides                                     #
##########################################################################################

uopz_set_return(
    'mysqli_stmt',
    'execute',
    function ($params = null) {
        __phuzz_ensure_sensor_tables($this);
        // Chạy lệnh execute gốc
        try {
            if ($params !== null) {
                $result = $this->execute($params); // Dành cho PHP 8.1+ hỗ trợ truyền mảng
            } else {
                $result = $this->execute();
            }
            $the_exception = null;
        } catch(Throwable $e) {
            $result = false;
            $the_exception = $e;
        }

        // 1. Nếu có lỗi (Error Logging)
        if ($result === false) {
            $errno = ($the_exception) ? -1 : $this->errno;
            $errstr = ($the_exception) ? $the_exception->getMessage() : $this->error;

            $json = json_encode([
                'function' => 'mysqli_stmt::execute',
                'params' => ['PREPARED_STMT'], // MySQLi_stmt không phơi bày query gốc ra ngoài nên tạm để là 'PREPARED_STMT'
                'errno' => $errno,
                'errstr' => $errstr,
            ]);
            __fuzzer_file_put_contents(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", $json . "\n", FILE_APPEND);
            chmod(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", 0777);

            if($the_exception != null) throw $the_exception;
        }

        // 2. Unconditional Logging (Query Events)
        $affected = ($result !== false) ? $this->affected_rows : -1;
        $json_event = json_encode([
            'function' => 'mysqli_stmt::execute',
            'params' => ['PREPARED_STMT'],
            'result' => ($result !== false),
            'affected_rows' => $affected,
            'errno' => ($result === false) ? (($the_exception) ? -1 : $this->errno) : 0,
            'errstr' => ($result === false) ? (($the_exception) ? $the_exception->getMessage() : $this->error) : '',
        ]);
        __fuzzer_file_put_contents(__FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . ".json", $json_event . "\n", FILE_APPEND);
        chmod(__FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . ".json", 0777);

        return $result;
    },
    true
);
?>