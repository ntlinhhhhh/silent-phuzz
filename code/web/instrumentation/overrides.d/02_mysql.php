<?php

##########################################################################################
#                                    mysqli overrides                                    #
##########################################################################################

uopz_set_return(
    'mysqli_query',
    function ($mysql, $query, $result_mode = MYSQLI_STORE_RESULT) {
        mysqli_report(MYSQLI_REPORT_ALL ^ MYSQLI_REPORT_STRICT);
        
        // 1. Khoi tao cac cau truc du lieu va log lich su fuzz
        __fuzzer_init_db_structures($mysql);
        __fuzzer_log_request_history($mysql);

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
                
                // 2. Kiem tra xem query co select tu bang duoc theo doi hay khong
                $matched_table = null;
                $query_lower = strtolower($query);
                foreach ($GLOBALS['__fuzzer_tracked_tables'] as $table) {
                    $tbl_lower = strtolower($table);
                    if (strpos($query_lower, "from " . $tbl_lower) !== false || strpos($query_lower, "join " . $tbl_lower) !== false || strpos($query_lower, "from `" . $tbl_lower . "`") !== false) {
                        $matched_table = $tbl_lower;
                        break;
                    }
                }
                if ($matched_table) {
                    $GLOBALS['__fuzzer_result_to_table'][spl_object_id($result)] = $matched_table;
                }
            } else {
                // Day la cau lenh ghi (INSERT/REPLACE/UPDATE) truc tiep
                $insert_id = mysqli_insert_id($mysql);
                if ($insert_id > 0 && preg_match('/^\s*(insert|replace)/i', $query) && isset($_SERVER['HTTP_X_FUZZER_COVID'])) {
                    $matched_table = null;
                    foreach ($GLOBALS['__fuzzer_tracked_tables'] as $table) {
                        if (preg_match('/\b' . $table . '\b/i', $query)) {
                            $matched_table = $table;
                            break;
                        }
                    }
                    if ($matched_table) {
                        $trace_id = "fuzz_" . $_SERVER['HTTP_X_FUZZER_COVID'];
                        $table_esc = mysqli_real_escape_string($mysql, $matched_table);
                        $trace_esc = mysqli_real_escape_string($mysql, $trace_id);
                        $id_esc = (int)$insert_id;
                        // Thuc hien cap nhat cot fuzz_trace_id bang ket noi hien tai
                        mysqli_query($mysql, "UPDATE `{$table_esc}` SET fuzz_trace_id = '{$trace_esc}' WHERE id = {$id_esc}");
                    }
                }
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

        // 3. Neu xay ra loi, thuc hien truy vet va ghi nhan loi theo trace_id nguon
        if ($result === false) {
            $error_json = json_encode([
                'function' => 'mysqli_query',
                'params' => [$query],
                'errno' => $errno,
                'errstr' => $errstr,
            ]);
            __fuzzer_file_put_contents(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", $error_json . "\n", FILE_APPEND);
            chmod(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", 0777);

            __fuzzer_correlate_and_log_error($query, $errno, $errstr);

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
        
        // 1. Khoi tao cac cau truc du lieu va log lich su fuzz
        __fuzzer_init_db_structures($this);
        __fuzzer_log_request_history($this);

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
                
                // 2. Kiem tra xem query co select tu bang duoc theo doi hay khong
                $matched_table = null;
                $query_lower = strtolower($query);
                foreach ($GLOBALS['__fuzzer_tracked_tables'] as $table) {
                    $tbl_lower = strtolower($table);
                    if (strpos($query_lower, "from " . $tbl_lower) !== false || strpos($query_lower, "join " . $tbl_lower) !== false || strpos($query_lower, "from `" . $tbl_lower . "`") !== false) {
                        $matched_table = $tbl_lower;
                        break;
                    }
                }
                if ($matched_table) {
                    $GLOBALS['__fuzzer_result_to_table'][spl_object_id($result)] = $matched_table;
                }
            } else {
                // Day la cau lenh ghi (INSERT/REPLACE/UPDATE) truc tiep
                $insert_id = $this->insert_id;
                if ($insert_id > 0 && preg_match('/^\s*(insert|replace)/i', $query) && isset($_SERVER['HTTP_X_FUZZER_COVID'])) {
                    $matched_table = null;
                    foreach ($GLOBALS['__fuzzer_tracked_tables'] as $table) {
                        if (preg_match('/\b' . $table . '\b/i', $query)) {
                            $matched_table = $table;
                            break;
                        }
                    }
                    if ($matched_table) {
                        $trace_id = "fuzz_" . $_SERVER['HTTP_X_FUZZER_COVID'];
                        $table_esc = $this->real_escape_string($matched_table);
                        $trace_esc = $this->real_escape_string($trace_id);
                        $id_esc = (int)$insert_id;
                        // Thuc hien cap nhat cot fuzz_trace_id bang ket noi hien tai
                        $this->query("UPDATE `{$table_esc}` SET fuzz_trace_id = '{$trace_esc}' WHERE id = {$id_esc}");
                    }
                }
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

        // 3. Neu xay ra loi, thuc hien truy vet va ghi nhan loi theo trace_id nguon
        if ($result === false) {
            $error_json = json_encode([
                'function' => 'mysqli::query',
                'params' => [$query],
                'errno' => $errno,
                'errstr' => $errstr,
            ]);
            __fuzzer_file_put_contents(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", $error_json . "\n", FILE_APPEND);
            chmod(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", 0777);

            __fuzzer_correlate_and_log_error($query, $errno, $errstr);

            if ($the_exception != null) {
                throw $the_exception;
            }
        }
        return $result;
    },
    true
);

if (!isset($GLOBALS['__fuzzer_prepared_queries'])) {
    $GLOBALS['__fuzzer_prepared_queries'] = [];
}

uopz_set_return(
    'mysqli',
    'prepare',
    function ($query) {
        $stmt = $this->prepare($query);
        if ($stmt !== false) {
            $stmt_id = spl_object_id($stmt);
            $GLOBALS['__fuzzer_prepared_queries'][$stmt_id] = $query;
        }
        return $stmt;
    },
    true
);

uopz_set_return(
    'mysqli_result',
    'fetch_assoc',
    function () {
        $row = $this->fetch_assoc();
        if ($row) {
            $res_id = spl_object_id($this);
            $table = $GLOBALS['__fuzzer_result_to_table'][$res_id] ?? null;
            
            // Neu dong nay den tu bang dang theo doi va co id khoa chinh
            if ($table && isset($row['id'])) {
                // Lay doi tuong ket noi MySQL tu internal property hoac tu context hien co
                // Cach don gian nhat: thuc hien shadow lookup su dung bien connection mysqli bat ky dang hoat dong
                // Ta co the lay link tu connection hien tai bang cach shadow query
                $db_conn = mysqli_connect('db', 'root', 'rootpassword', 'silent_testbed');
                if ($db_conn) {
                    __fuzzer_shadow_lookup($db_conn, $table, $row['id'], $row);
                    mysqli_close($db_conn);
                }
            }
        }
        return $row;
    },
    true
);