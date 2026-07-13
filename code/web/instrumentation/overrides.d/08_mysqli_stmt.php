<?php
##########################################################################################
#               mysqli_stmt overrides - Data Provenance Tracking                         #
##########################################################################################

// Global buffer để lưu bound parameters qua bind_param
if (!isset($GLOBALS['__fuzzer_bound_params'])) {
    $GLOBALS['__fuzzer_bound_params'] = [];
}
if (!isset($GLOBALS['__fuzzer_prepared_queries'])) {
    $GLOBALS['__fuzzer_prepared_queries'] = [];
}

// Hook mysqli_stmt::bind_param để capture giá trị bound
uopz_set_return(
    'mysqli_stmt',
    'bind_param',
    function ($types, &...$vars) {
        // Lưu bản sao các giá trị bound vào global buffer
        $bound_values = [];
        foreach ($vars as $v) {
            $bound_values[] = $v;
        }
        // Key bằng spl_object_id để phân biệt các stmt khác nhau
        $stmt_id = spl_object_id($this);
        $GLOBALS['__fuzzer_bound_params'][$stmt_id] = [
            'types' => $types,
            'values' => $bound_values,
        ];
        // Gọi hàm gốc
        return $this->bind_param($types, ...$vars);
    },
    true
);

// Hook mysqli_stmt::execute để capture thao tác ghi + giá trị bound
uopz_set_return(
    'mysqli_stmt',
    'execute',
    function () {
        $start_time = microtime(true);
        $the_exception = null;
        try {
            $result = $this->execute();
        } catch(Throwable $e) {
            $result = false;
            $the_exception = $e;
        }
        $execution_time = microtime(true) - $start_time;

        $stmt_id = spl_object_id($this);
        $bound_data = $GLOBALS['__fuzzer_bound_params'][$stmt_id] ?? null;
        $query_template = $GLOBALS['__fuzzer_prepared_queries'][$stmt_id] ?? '';

        // Lấy thông tin file gọi
        $backtrace = debug_backtrace(DEBUG_BACKTRACE_IGNORE_ARGS, 3);
        $caller_file = isset($backtrace[1]['file']) ? $backtrace[1]['file'] : 'unknown';
        $caller_line = isset($backtrace[1]['line']) ? $backtrace[1]['line'] : 0;

        // Xác định đây có phải thao tác ghi (INSERT/UPDATE/REPLACE) không
        $affected_rows = $this->affected_rows;
        $is_write = ($affected_rows > 0 && preg_match('/^\s*(insert|update|replace)/i', $query_template));

        // 1. Tự động tiêm fuzz_trace_id vào dòng vừa ghi trên các bảng theo dõi
        if ($is_write && $result !== false && isset($_SERVER['HTTP_X_FUZZER_COVID'])) {
            $db_conn = mysqli_connect('db', 'root', 'rootpassword', 'silent_testbed');
            if ($db_conn) {
                // Đảm bảo cấu trúc DB và bảng theo dõi đã được khởi tạo
                __fuzzer_init_db_structures($db_conn);
                __fuzzer_log_request_history($db_conn);

                // Xác định bảng đích được cập nhật
                $matched_table = null;
                foreach ($GLOBALS['__fuzzer_tracked_tables'] as $table) {
                    if (preg_match('/\b' . $table . '\b/i', $query_template)) {
                        $matched_table = $table;
                        break;
                    }
                }
                if ($matched_table) {
                    $trace_id = "fuzz_" . $_SERVER['HTTP_X_FUZZER_COVID'];
                    $insert_id = $this->insert_id;
                    if ($insert_id > 0) {
                        $table_esc = mysqli_real_escape_string($db_conn, $matched_table);
                        $trace_esc = mysqli_real_escape_string($db_conn, $trace_id);
                        $id_esc = (int)$insert_id;
                        mysqli_query($db_conn, "UPDATE `{$table_esc}` SET fuzz_trace_id = '{$trace_esc}' WHERE id = {$id_esc}");
                    }
                }
                mysqli_close($db_conn);
            }
        }

        $event = [
            'function' => 'mysqli_stmt::execute',
            'query' => $query_template,
            'success' => ($result !== false),
            'is_write_operation' => $is_write,
            'affected_rows' => $affected_rows,
            'execution_time' => $execution_time,
            'bound_params' => $bound_data,
            'caller_file' => $caller_file,
            'caller_line' => $caller_line,
            'errno' => $this->errno,
            'errstr' => $this->error,
        ];

        // Cũng ghi vào query events cho mục đích tổng hợp
        $json = json_encode($event);
        __fuzzer_file_put_contents(
            __FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . ".json",
            $json . "\n", FILE_APPEND
        );
        chmod(__FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . ".json", 0777);

        // Ghi error report nếu thất bại
        if ($result === false) {
            $error_json = json_encode([
                'function' => 'mysqli_stmt::execute',
                'params' => $bound_data ? $bound_data['values'] : [],
                'errno' => $this->errno,
                'errstr' => $this->error,
            ]);
            __fuzzer_file_put_contents(
                __FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json",
                $error_json . "\n", FILE_APPEND
            );
            chmod(__FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . ".json", 0777);

            __fuzzer_correlate_and_log_error($query_template, $this->errno, $this->error);

            if ($the_exception != null) {
                throw $the_exception;
            }
        }
        return $result;
    },
    true
);
?>