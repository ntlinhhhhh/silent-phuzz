<?php
// overrides.d/00_helper.php (Core Helper Library)

if (!isset($GLOBALS['__PHUZZ_SUPPRESS_HOOKS'])) {
    $GLOBALS['__PHUZZ_SUPPRESS_HOOKS'] = false;
}

if (!isset($GLOBALS['__PHUZZ_EVENT_SEQ'])) {
    $GLOBALS['__PHUZZ_EVENT_SEQ'] = 0;
}

function __phuzz_next_event_seq() {
    $GLOBALS['__PHUZZ_EVENT_SEQ']++;
    return $GLOBALS['__PHUZZ_EVENT_SEQ'];
}

function __phuzz_timer_start() {
    if (function_exists('hrtime')) {
        return ['clock' => 'hrtime', 'value' => hrtime(true)];
    }
    return ['clock' => 'microtime', 'value' => microtime(true)];
}

function __phuzz_duration_ms(array $started_at) {
    if ($started_at['clock'] === 'hrtime') {
        return round((hrtime(true) - $started_at['value']) / 1000000, 6);
    }
    return round((microtime(true) - $started_at['value']) * 1000, 6);
}

function __phuzz_utc_timestamp() {
    $now = microtime(true);
    $seconds = (int) floor($now);
    $microseconds = (int) floor(($now - $seconds) * 1000000);
    return gmdate('Y-m-d\TH:i:s', $seconds) . sprintf('.%06dZ', $microseconds);
}

function __phuzz_json_safe($value) {
    if ($value === null || is_bool($value) || is_int($value) || is_float($value) || is_string($value)) {
        return $value;
    }
    if (is_array($value)) {
        $safe = [];
        foreach ($value as $key => $item) {
            $safe[$key] = __phuzz_json_safe($item);
        }
        return $safe;
    }
    if (is_object($value) && method_exists($value, '__toString')) {
        return (string) $value;
    }
    if (is_object($value)) {
        return ['__class' => get_class($value)];
    }
    if (is_resource($value)) {
        return ['__resource' => get_resource_type($value)];
    }
    return (string) $value;
}

function __phuzz_extract_fuzz_markers($value) {
    if (__phuzz_phase() !== 'fuzzing') {
        return [];
    }

    $markers = [];
    $pattern = '/(?<![0-9A-Za-z_])pz_[0-9A-Za-z_]+(?![0-9A-Za-z_])/';
    $visit = function ($item) use (&$visit, &$markers, $pattern) {
        if (is_array($item)) {
            foreach ($item as $nested) {
                $visit($nested);
            }
            return;
        }
        if (is_object($item) && method_exists($item, '__toString')) {
            $item = (string) $item;
        }
        if (!is_string($item)) {
            return;
        }
        $matches = [];
        $matched = @preg_match_all($pattern, $item, $matches);
        if ($matched) {
            foreach ($matches[0] as $marker) {
                if (!in_array($marker, $markers, true)) {
                    $markers[] = $marker;
                }
            }
        }
    };
    $visit($value);
    return $markers;
}

function __phuzz_build_fuzz_markers($sql_text, $sql_template, $bind_params) {
    return [
        'sql_text' => __phuzz_extract_fuzz_markers($sql_text),
        'sql_template' => __phuzz_extract_fuzz_markers($sql_template),
        'bind_params' => __phuzz_extract_fuzz_markers($bind_params),
    ];
}

function __phuzz_with_fuzz_markers(array $record, array $markers): array {
    if (__phuzz_phase() === 'fuzzing') {
        $record['markers'] = $markers;
    }
    return $record;
}

function __phuzz_error_message($value) {
    if (is_array($value)) {
        if (isset($value[2]) && $value[2] !== null && $value[2] !== '') {
            return (string) $value[2];
        }
        $parts = [];
        foreach ($value as $part) {
            if ($part !== null && $part !== '') {
                $parts[] = (string) $part;
            }
        }
        return implode(' | ', $parts);
    }
    return $value === null ? '' : (string) $value;
}

function __phuzz_json_encode($value) {
    $options = JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE;
    if (defined('JSON_INVALID_UTF8_SUBSTITUTE')) {
        $options |= JSON_INVALID_UTF8_SUBSTITUTE;
    }
    return json_encode(__phuzz_json_safe($value), $options);
}

function __phuzz_write_json_line($path, array $record) {
    $json = __phuzz_json_encode($record);
    if ($json === false) {
        error_log('[Phuzz Event Error] Failed to encode SQL event: ' . json_last_error_msg());
        return;
    }
    __fuzzer_file_put_contents($path, $json . "\n", FILE_APPEND);
    @chmod($path, 0777);
}

function __phuzz_write_query_event(
    $function,
    $event_seq,
    $sql_text,
    $sql_template,
    $bind_params,
    $success,
    $errno,
    $errstr,
    $affected_rows,
    $duration_ms,
    $timestamp,
    array $markers
) {
    __phuzz_write_json_line(
        __FUZZER__MYSQL_QUERY_EVENTS_PATH . __FUZZER__COVID . '.json',
        __phuzz_with_fuzz_markers([
            'current_coverage_id' => __FUZZER__COVID,
            'event_seq' => $event_seq,
            'phase' => __phuzz_phase(),
            'endpoint' => __phuzz_endpoint_context(),
            'function' => $function,
            'sql_text' => $sql_text,
            'sql_template' => $sql_template,
            'bind_params' => $bind_params === null ? null : __phuzz_json_safe($bind_params),
            'success' => (bool) $success,
            'errno' => $errno,
            'errstr' => __phuzz_error_message($errstr),
            'affected_rows' => $affected_rows,
            'duration_ms' => $duration_ms,
            'timestamp' => $timestamp,
        ], $markers)
    );
}

function __phuzz_write_mysql_error(
    $function,
    array $params,
    $errno,
    $errstr,
    $event_seq,
    array $markers
) {
    // Keep the four legacy fields unchanged; append correlation metadata only.
    __phuzz_write_json_line(
        __FUZZER__MYSQL_ERRORS_PATH . __FUZZER__COVID . '.json',
        __phuzz_with_fuzz_markers([
            'function' => $function,
            'params' => $params,
            'errno' => $errno,
            'errstr' => $errstr,
            'current_coverage_id' => __FUZZER__COVID,
            'event_seq' => $event_seq,
            'phase' => __phuzz_phase(),
            'endpoint' => __phuzz_endpoint_context(),
        ], $markers)
    );
}

// thực hiện khóa hook để tránh vòng lặp vô hạn khi gọi các hàm PDO hoặc mysqli bên trong các hàm này
function __phuzz_run_unhooked(callable $fn) {
    $prev = $GLOBALS['__PHUZZ_SUPPRESS_HOOKS'];
    $GLOBALS['__PHUZZ_SUPPRESS_HOOKS'] = true;
    try {
        return $fn();
    } finally {
        $GLOBALS['__PHUZZ_SUPPRESS_HOOKS'] = $prev;
    }
}

// tạo một WeakMap để lưu trữ thông tin về các prepared statement và kết nối cơ sở dữ liệu tương ứng
if (!isset($GLOBALS['__PHUZZ_STMT_MAP'])) {
    $GLOBALS['__PHUZZ_STMT_MAP'] = new WeakMap();
}

function __phuzz_remember_stmt($stmt, $connection, string $sql): void {
    if ($stmt instanceof mysqli_stmt || $stmt instanceof PDOStatement) {
        $GLOBALS['__PHUZZ_STMT_MAP'][$stmt] = [
            'conn' => $connection,
            'sql' => $sql,
            'bound_values' => [],
            'bound_references' => [],
        ];
    }
}

function __phuzz_stmt_meta($stmt) {
    if (!($stmt instanceof mysqli_stmt) && !($stmt instanceof PDOStatement)) {
        return [];
    }
    if (!isset($GLOBALS['__PHUZZ_STMT_MAP'][$stmt])) {
        return [];
    }
    return $GLOBALS['__PHUZZ_STMT_MAP'][$stmt];
}

function __phuzz_normalize_parameter_key($parameter) {
    return is_string($parameter) ? ltrim($parameter, ':') : $parameter;
}

function __phuzz_remember_stmt_bound_value($stmt, $parameter, $value) {
    $meta = __phuzz_stmt_meta($stmt);
    if (!$meta) {
        return;
    }
    $key = __phuzz_normalize_parameter_key($parameter);
    $meta['bound_values'][$key] = $value;
    unset($meta['bound_references'][$key]);
    $GLOBALS['__PHUZZ_STMT_MAP'][$stmt] = $meta;
}

function __phuzz_remember_stmt_bound_reference($stmt, $parameter, &$value) {
    $meta = __phuzz_stmt_meta($stmt);
    if (!$meta) {
        return;
    }
    $key = __phuzz_normalize_parameter_key($parameter);
    $meta['bound_references'][$key] =& $value;
    unset($meta['bound_values'][$key]);
    $GLOBALS['__PHUZZ_STMT_MAP'][$stmt] = $meta;
}

function __phuzz_remember_stmt_bound_references($stmt, array &$values) {
    $meta = __phuzz_stmt_meta($stmt);
    if (!$meta) {
        return;
    }
    $meta['bound_values'] = [];
    $meta['bound_references'] = [];
    foreach ($values as $key => &$value) {
        $meta['bound_references'][$key] =& $value;
    }
    unset($value);
    $GLOBALS['__PHUZZ_STMT_MAP'][$stmt] = $meta;
}

function __phuzz_normalize_bind_params($params) {
    if ($params === null || !is_array($params)) {
        return $params;
    }
    $normalized = [];
    foreach ($params as $key => $value) {
        $normalized[__phuzz_normalize_parameter_key($key)] = __phuzz_json_safe($value);
    }
    return $normalized;
}

function __phuzz_export_bound_params(array $values) {
    if (!$values) {
        return [];
    }
    $all_numeric = true;
    foreach (array_keys($values) as $key) {
        if (!is_int($key)) {
            $all_numeric = false;
            break;
        }
    }
    if ($all_numeric) {
        ksort($values, SORT_NUMERIC);
        return array_values(array_map('__phuzz_json_safe', $values));
    }
    ksort($values, SORT_STRING);
    return array_map('__phuzz_json_safe', $values);
}

function __phuzz_resolve_bind_params_for_stmt($stmt) {
    $meta = __phuzz_stmt_meta($stmt);
    if (!$meta) {
        return null;
    }
    $values = $meta['bound_values'] ?? [];
    foreach (($meta['bound_references'] ?? []) as $key => &$value) {
        $values[$key] = $value;
    }
    unset($value);
    return __phuzz_export_bound_params($values);
}

function __phuzz_resolve_connection_for_stmt($stmt) {
    $meta = __phuzz_stmt_meta($stmt);
    return $meta['conn'] ?? null;
}

function __phuzz_resolve_sql_for_stmt($stmt): ?string {
    $meta = __phuzz_stmt_meta($stmt);
    return $meta['sql'] ?? null;
}

function __phuzz_phase(): string {
    $request_phase = $_SERVER['HTTP_X_PHUZZ_PHASE'] ?? null;
    $phase = is_string($request_phase) && $request_phase !== ''
        ? $request_phase
        : (getenv('PHUZZ_PHASE') ?: 'legacy');

    if (!in_array($phase, ['profiling', 'fuzzing', 'legacy'], true)) {
        return 'legacy';
    }

    return $phase;
}

function __phuzz_endpoint_context(): array {
    $method = strtoupper((string) ($_SERVER['REQUEST_METHOD'] ?? ''));
    $uri = (string) ($_SERVER['REQUEST_URI'] ?? '');
    $path = parse_url($uri, PHP_URL_PATH);

    return [
        'method' => $method,
        'path' => is_string($path) ? $path : '',
    ];
}
