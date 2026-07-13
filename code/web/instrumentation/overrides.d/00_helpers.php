<?php
// helpers.php - Cac ham tro giup truy vet nang cao cho Fuzzer

// Tu dong khoi tao cau truc bang va mapping cot tracking
function __fuzzer_init_db_structures($mysql) {
    if ($GLOBALS['__fuzzer_db_initialized']) {
        return;
    }
    
    // 1. Tao bang fuzz_history neu chua ton tai
    $create_history = "CREATE TABLE IF NOT EXISTS fuzz_history (
        fuzz_trace_id VARCHAR(100) NOT NULL PRIMARY KEY,
        url TEXT NOT NULL,
        method VARCHAR(10) NOT NULL,
        payload_sample TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    ) ENGINE=InnoDB";
    mysqli_query($mysql, $create_history);

    // 2. Tu dong quet tat ca cac bang nghiep vu trong database (loai tru cac bang he thong cua fuzzer)
    $get_tables = "SELECT TABLE_NAME FROM information_schema.tables 
                   WHERE TABLE_SCHEMA = DATABASE() 
                     AND TABLE_NAME NOT IN ('fuzz_history', 'phuzz_sensor', '__phuzz_sensor_insert', '__phuzz_sensor_update', '__phuzz_sensor_delete')
                     AND TABLE_TYPE = 'BASE TABLE'";
    $res_tables = mysqli_query($mysql, $get_tables);
    if ($res_tables) {
        $tracked = [];
        while ($row = mysqli_fetch_row($res_tables)) {
            $table_name = strtolower($row[0]);
            
            // Kiem tra xem bang co cot fuzz_trace_id chua
            $check_col = "SELECT COLUMN_NAME FROM information_schema.columns 
                          WHERE TABLE_NAME = '{$table_name}' AND COLUMN_NAME = 'fuzz_trace_id' AND TABLE_SCHEMA = DATABASE()";
            $tracked[] = $table_name;
        }
        $GLOBALS['__fuzzer_tracked_tables'] = $tracked;
    }
    
    $GLOBALS['__fuzzer_db_initialized'] = true;
}

// Log lich su fuzzing cho request hien tai
function __fuzzer_log_request_history($mysql) {
    if ($GLOBALS['__fuzzer_history_logged'] || !isset($_SERVER['HTTP_X_FUZZER_COVID'])) {
        return;
    }

    $trace_id = "fuzz_" . $_SERVER['HTTP_X_FUZZER_COVID'];
    $url = $_SERVER['REQUEST_URI'] ?? 'unknown';
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    
    // Doc sample payload tu input hoac query
    $payload_sample = "";
    if ($method === 'POST') {
        $payload_sample = json_encode($_POST);
    } else {
        $payload_sample = json_encode($_GET);
    }

    $stmt = mysqli_prepare($mysql, "INSERT INTO fuzz_history (fuzz_trace_id, url, method, payload_sample) VALUES (?, ?, ?, ?) ON DUPLICATE KEY UPDATE fuzz_trace_id=fuzz_trace_id");
    if ($stmt) {
        mysqli_stmt_bind_param($stmt, "ssss", $trace_id, $url, $method, $payload_sample);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);
    }

    $GLOBALS['__fuzzer_history_logged'] = true;
}

// Ham quet cac cell trong dong de nap vao Value-based Buffer
function __fuzzer_map_row_values($row, $fuzz_trace_id) {
    if (!$fuzz_trace_id) return;
    foreach ($row as $k => $v) {
        if ($k !== 'fuzz_trace_id' && $k !== 'id' && is_string($v) && strlen($v) >= 3) {
            $GLOBALS['__fuzzer_loaded_traces_val'][$v] = $fuzz_trace_id;
        }
    }
}

// Ham thuc hien truy van shadow de lay fuzz_trace_id bang khoa chinh
function __fuzzer_shadow_lookup($mysql, $table, $id_val, $row) {
    $table_esc = mysqli_real_escape_string($mysql, $table);
    $id_esc = (int)$id_val;
    $res = mysqli_query($mysql, "SELECT fuzz_trace_id FROM `{$table_esc}` WHERE id = {$id_esc}");
    if ($res) {
        $row_trace = mysqli_fetch_assoc($res);
        if ($row_trace && !empty($row_trace['fuzz_trace_id'])) {
            __fuzzer_map_row_values($row, $row_trace['fuzz_trace_id']);
        }
    }
}

// Truyen vet nguoc de lay trace_id tu cau truy van bi loi
function __fuzzer_correlate_and_log_error($query_str, $errno, $errstr) {
    $matched_trace_id = null;
    $query_lower = strtolower($query_str);

    // Kiem tra xem trong query bi loi co chua gia tri nao trong Loaded Traces hay khong
    foreach ($GLOBALS['__fuzzer_loaded_traces_val'] as $val => $trace_id) {
        // Lay phan chuoi an toan de so khop (bo dau nhay don/kep hoac ki tu dac biet neu co)
        $clean_val = trim($val, "'\" \t\n\r\0\x0B");
        if (strlen($clean_val) < 3) {
            continue;
        }
        
        // Ho tro so khop ca chuoi da duoc ma hoa HTML entities (vd: &lt;script&gt;) va chuoi thong thuong
        $html_decoded_val = html_entity_decode($clean_val, ENT_QUOTES);
        
        if (strpos($query_lower, strtolower($clean_val)) !== false || 
            strpos($query_lower, strtolower($html_decoded_val)) !== false) {
            $matched_trace_id = $trace_id;
            break;
        }
    }

    // Neu tim thay trace_id, ghi log loi dung ten fuzz_trace_id do
    if ($matched_trace_id) {
        $error_json = json_encode([
            'function' => 'mysqli_query_error_correlate',
            'params' => [$query_str],
            'errno' => $errno,
            'errstr' => $errstr,
        ]);
        // Ghi truc tiep vao file log voi ten id nguon
        __fuzzer_file_put_contents(__FUZZER__MYSQL_ERRORS_PATH . $matched_trace_id . ".json", $error_json . "\n", FILE_APPEND);
        chmod(__FUZZER__MYSQL_ERRORS_PATH . $matched_trace_id . ".json", 0777);
    }
}
