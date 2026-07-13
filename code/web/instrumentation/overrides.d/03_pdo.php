<?php
##########################################################################################
#                                     PDO overrides                                     #
##########################################################################################
uopz_set_return(
    'PDO',
    'query',
    function ($query, $fetchMode = null) {
        $start_time = microtime(true);
        $the_exception = null;
        try{
            $result = $this->query($query, $fetchMode);
        }catch(Throwable $e) {
            $result = false;
            $the_exception = $e;
        }
        $execution_time = microtime(true) - $start_time;

        $rows_affected = -1;
        $returned_rows = -1;
        $errno = 0;
        $errstr = '';

        if ($result === false) {
            if($the_exception) {
                $errno = -1;
                $errstr = $the_exception->getMessage();
            } else {
                $errno = $this->errorCode();
                $errstr = $this->errorInfo();
            }
        } else {
            if ($result instanceof PDOStatement) {
                $returned_rows = $result->rowCount();
            }
        }

        $event = [
            'function' => 'PDO::query',
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

        if ($result === false) {
            $error_json = json_encode([
                'function' => 'PDO::query',
                'params' => [$query],
                'errno' => $errno,
                'errstr' => $errstr,
            ]);
            __fuzzer_file_put_contents(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", $error_json . "\n", FILE_APPEND);
            chmod(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", 0777);
            if($the_exception != null) {
                throw $the_exception;
            }
        }
        return $result;
    },
    true
);

uopz_set_return(
    'PDO',
    'query',
    function ($query, $fetchMode = PDO::FETCH_COLUMN, $colno = null) {
        $start_time = microtime(true);
        $the_exception = null;
        try{
            $result = $this->query($query, $fetchMode, $colno);
        }catch(Throwable $e) {
            $result = false;
            $the_exception = $e;
        }
        $execution_time = microtime(true) - $start_time;

        $rows_affected = -1;
        $returned_rows = -1;
        $errno = 0;
        $errstr = '';

        if ($result === false) {
            if($the_exception) {
                $errno = -1;
                $errstr = $the_exception->getMessage();
            } else {
                $errno = $this->errorCode();
                $errstr = $this->errorInfo();
            }
        } else {
            if ($result instanceof PDOStatement) {
                $returned_rows = $result->rowCount();
            }
        }

        $event = [
            'function' => 'PDO::query',
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

        if ($result === false) {
            $error_json = json_encode([
                'function' => 'PDO::query',
                'params' => [$query],
                'errno' => $errno,
                'errstr' => $errstr,
            ]);
            __fuzzer_file_put_contents(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", $error_json . "\n", FILE_APPEND);
            chmod(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", 0777);
            if($the_exception != null) {
                throw $the_exception;
            }
        }
        return $result;
    },
    true
);
uopz_set_return(
    'PDO',
    'query',
    function ($query, $fetchMode = PDO::FETCH_CLASS, $classname = null, $constructorArgs = null) {
        $start_time = microtime(true);
        $the_exception = null;
        try{
            $result = $this->query($query, $fetchMode, $classname, $constructorArgs);
        }catch(Throwable $e) {
            $result = false;
            $the_exception = $e;
        }
        $execution_time = microtime(true) - $start_time;

        $rows_affected = -1;
        $returned_rows = -1;
        $errno = 0;
        $errstr = '';

        if ($result === false) {
            if($the_exception) {
                $errno = -1;
                $errstr = $the_exception->getMessage();
            } else {
                $errno = $this->errorCode();
                $errstr = $this->errorInfo();
            }
        } else {
            if ($result instanceof PDOStatement) {
                $returned_rows = $result->rowCount();
            }
        }

        $event = [
            'function' => 'PDO::query',
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

        if ($result === false) {
            $error_json = json_encode([
                'function' => 'PDO::query',
                'params' => [$query],
                'errno' => $errno,
                'errstr' => $errstr,
            ]);
            __fuzzer_file_put_contents(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", $error_json . "\n", FILE_APPEND);
            chmod(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", 0777);
            if($the_exception != null) {
                throw $the_exception;
            }
        }
        return $result;
    },
    true
);


uopz_set_return(
    'PDO',
    'query',
    function ($query, $fetchMode = PDO::FETCH_INTO, $object = null) {
        $start_time = microtime(true);
        $the_exception = null;
        try{
            $result = $this->query($query, $fetchMode, $object);
        }catch(Throwable $e) {
            $result = false;
            $the_exception = $e;
        }
        $execution_time = microtime(true) - $start_time;

        $rows_affected = -1;
        $returned_rows = -1;
        $errno = 0;
        $errstr = '';

        if ($result === false) {
            if($the_exception) {
                $errno = -1;
                $errstr = $the_exception->getMessage();
            } else {
                $errno = $this->errorCode();
                $errstr = $this->errorInfo();
            }
        } else {
            if ($result instanceof PDOStatement) {
                $returned_rows = $result->rowCount();
            }
        }

        $event = [
            'function' => 'PDO::query',
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

        if ($result === false) {
            $error_json = json_encode([
                'function' => 'PDO::query',
                'params' => [$query],
                'errno' => $errno,
                'errstr' => $errstr,
            ]);
            __fuzzer_file_put_contents(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", $error_json . "\n", FILE_APPEND);
            chmod(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", 0777);
            if($the_exception != null) {
                throw $the_exception;
            }
        }
        return $result;
    },
    true
);

uopz_set_return(
    'PDO',
    'exec',
    function ($statement) {
        $start_time = microtime(true);
        $the_exception = null;
        try{
            $result = $this->exec($statement);
        }catch(Throwable $e) {
            $result = false;
            $the_exception = $e;
        }
        $execution_time = microtime(true) - $start_time;

        $rows_affected = -1;
        $returned_rows = 0;
        $errno = 0;
        $errstr = '';

        if ($result === false) {
            if($the_exception) {
                $errno = -1;
                $errstr = $the_exception->getMessage();
            } else {
                $errno = $this->errorCode();
                $errstr = $this->errorInfo();
            }
        } else {
            $rows_affected = $result;
        }

        $event = [
            'function' => 'PDO::exec',
            'query' => $statement,
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

        if ($result === false) {
            $error_json = json_encode([
                'function' => 'PDO::exec',
                'params' => [$statement],
                'errno' => $errno,
                'errstr' => $errstr,
            ]);
            __fuzzer_file_put_contents(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", $error_json . "\n", FILE_APPEND);
            chmod(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", 0777);
            if($the_exception != null) {
                throw $the_exception;
            }
        }
        return $result;
    },
    true
);

uopz_set_return(
    'PDOStatement',
    'execute',
    function ($params = null) {
        $start_time = microtime(true);
        $the_exception = null;
        try {
            $result = $this->execute($params);
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
                $error_info = $this->errorInfo();
                $errno = $this->errorCode();
                $errstr = isset($error_info[2]) ? $error_info[2] : '';
            }
        } else {
            $rows_affected = $this->rowCount();
            $returned_rows = $this->rowCount();
        }

        $query = $this->queryString;

        // 1. Kiem tra xem query co select tu bang duoc theo doi hay khong
        if ($result !== false) {
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
                $GLOBALS['__fuzzer_result_to_table'][spl_object_id($this)] = $matched_table;
            }
        }

        $event = [
            'function' => 'PDOStatement::execute',
            'query' => $query,
            'success' => ($result !== false),
            'rows_affected' => $rows_affected,
            'returned_rows' => $returned_rows,
            'execution_time' => $execution_time,
            'errno' => $errno,
            'errstr' => $errstr,
        ];

        // Ghi event log truy vấn
        $json = json_encode($event);
        __fuzzer_file_put_contents(__FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . ".json", $json . "\n", FILE_APPEND);
        chmod(__FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . ".json", 0777);

        if ($result === false) {
            $error_json = json_encode([
                'function' => 'PDOStatement::execute',
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

// Hook PDOStatement::fetch de capture du lieu dong vao buffer tracking
uopz_set_return(
    'PDOStatement',
    'fetch',
    function ($mode = null, $cursorOrientation = null, $cursorOffset = null) {
        $row = $this->fetch($mode, $cursorOrientation, $cursorOffset);
        if ($row && is_array($row)) {
            $stmt_id = spl_object_id($this);
            $table = $GLOBALS['__fuzzer_result_to_table'][$stmt_id] ?? null;
            if ($table && isset($row['id'])) {
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