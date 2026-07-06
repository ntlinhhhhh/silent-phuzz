<?php

##########################################################################################
#                                    mysqli overrides                                    #
##########################################################################################

uopz_set_return(
    'mysqli_query',
    function ($mysql, $query, $result_mode = MYSQLI_STORE_RESULT) {
        mysqli_report(MYSQLI_REPORT_ALL ^ MYSQLI_REPORT_STRICT);
        $start_time = microtime(true);
        $the_exception = null;
        try {
            $result = mysqli_query($mysql, $query, $result_mode);
        } catch(Throwable $e) {
            $result = false;
            $the_exception = $e;
        }
        $execution_time = microtime(true) - $start_time;

        $rows_affected = -1;
        $returned_rows = -1;
        $errno = 0;
        $errstr = '';

        if ($result === false) {
            if ($the_exception) {
                $errno = -1;
                $errstr = $the_exception->getMessage();
            } else {
                $errno = mysqli_errno($mysql);
                $errstr = mysqli_error($mysql);
            }
        } else {
            $rows_affected = mysqli_affected_rows($mysql);
            if ($result instanceof mysqli_result) {
                $returned_rows = mysqli_num_rows($result);
            }
        }

        $event = [
            'function' => 'mysqli_query',
            'query' => $query,
            'success' => ($result !== false),
            'rows_affected' => $rows_affected,
            'returned_rows' => $returned_rows,
            'execution_time' => $execution_time,
            'errno' => $errno,
            'errstr' => $errstr,
        ];

        // Write query event log
        $json = json_encode($event);
        __fuzzer_file_put_contents(__FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . ".json", $json . "\n", FILE_APPEND);
        chmod(__FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . ".json", 0777);

        // Also write to mysql-errors if query failed
        if ($result === false) {
            $error_json = json_encode([
                'function' => 'mysqli_query',
                'params' => [$query],
                'errno' => $errno,
                'errstr' => $errstr,
            ]);
            __fuzzer_file_put_contents(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", $error_json . "\n", FILE_APPEND);
            chmod(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", 0777);

            if ($the_exception != null) {
                throw $the_exception;
            }
        }
        return $result;
    },
    true
);

uopz_set_return(
    'mysqli',
    'query',
    function ($query, $result_mode = MYSQLI_STORE_RESULT) {
        mysqli_report(MYSQLI_REPORT_ALL ^ MYSQLI_REPORT_STRICT);
        $start_time = microtime(true);
        $the_exception = null;
        try {
            $result = $this->query($query, $result_mode);
        } catch(Throwable $e) {
            $result = false;
            $the_exception = $e;
        }
        $execution_time = microtime(true) - $start_time;

        $rows_affected = -1;
        $returned_rows = -1;
        $errno = 0;
        $errstr = '';

        if ($result === false) {
            if ($the_exception) {
                $errno = -1;
                $errstr = $the_exception->getMessage();
            } else {
                $errno = $this->errno;
                $errstr = $this->error;
            }
        } else {
            $rows_affected = $this->affected_rows;
            if ($result instanceof mysqli_result) {
                $returned_rows = $result->num_rows;
            }
        }

        $event = [
            'function' => 'mysqli::query',
            'query' => $query,
            'success' => ($result !== false),
            'rows_affected' => $rows_affected,
            'returned_rows' => $returned_rows,
            'execution_time' => $execution_time,
            'errno' => $errno,
            'errstr' => $errstr,
        ];

        // Write query event log
        $json = json_encode($event);
        __fuzzer_file_put_contents(__FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . ".json", $json . "\n", FILE_APPEND);
        chmod(__FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . ".json", 0777);

        // Also write to mysql-errors if query failed
        if ($result === false) {
            $error_json = json_encode([
                'function' => 'mysqli::query',
                'params' => [$query],
                'errno' => $errno,
                'errstr' => $errstr,
            ]);
            __fuzzer_file_put_contents(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", $error_json . "\n", FILE_APPEND);
            chmod(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", 0777);

            if ($the_exception != null) {
                throw $the_exception;
            }
        }
        return $result;
    },
    true
);
