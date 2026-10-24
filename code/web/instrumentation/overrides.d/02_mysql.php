<?php
// overrides.d/02_mysql.php

uopz_set_return(
    'mysqli_query',
    function ($mysql, $query, $result_mode = MYSQLI_STORE_RESULT) {
        if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
            return mysqli_query($mysql, $query, $result_mode);
        }

        $event_seq = __phuzz_next_event_seq();
        $markers = __phuzz_build_fuzz_markers($query, null, null);
        $started_at = __phuzz_timer_start();
        try {
            $result = mysqli_query($mysql, $query, $result_mode);
            $the_exception = null;
        } catch (Throwable $e) {
            $result = false;
            $the_exception = $e;
        }
        $duration_ms = __phuzz_duration_ms($started_at);
        $timestamp = __phuzz_utc_timestamp();

        if ($result === false) {
            $errno = ($the_exception) ? -1 : mysqli_errno($mysql);
            $errstr = ($the_exception) ? $the_exception->getMessage() : mysqli_error($mysql);
            __phuzz_write_mysql_error(
                'mysqli_query',
                [$query],
                $errno,
                $errstr,
                $event_seq,
                $markers
            );
            if ($the_exception !== null) {
                throw $the_exception;
            }
        } else {
            $affected = mysqli_affected_rows($mysql);
            __phuzz_write_query_success(
                'mysqli_query',
                $event_seq,
                $query,
                null,
                null,
                $affected,
                $duration_ms,
                $timestamp,
                $markers
            );
        }
        return $result;
    },
    true
);

uopz_set_return(
    'mysqli',
    'query',
    function ($query, $result_mode = MYSQLI_STORE_RESULT) {
        if ($GLOBALS['__PHUZZ_SUPPRESS_HOOKS']) {
            return $this->query($query, $result_mode);
        }

        $event_seq = __phuzz_next_event_seq();
        $markers = __phuzz_build_fuzz_markers($query, null, null);
        $started_at = __phuzz_timer_start();
        try {
            $result = $this->query($query, $result_mode);
            $the_exception = null;
        } catch (Throwable $e) {
            $result = false;
            $the_exception = $e;
        }
        $duration_ms = __phuzz_duration_ms($started_at);
        $timestamp = __phuzz_utc_timestamp();

        if ($result === false) {
            $errno = ($the_exception) ? -1 : $this->errno;
            $errstr = ($the_exception) ? $the_exception->getMessage() : $this->error;
            __phuzz_write_mysql_error(
                'mysqli::query',
                [$query],
                $errno,
                $errstr,
                $event_seq,
                $markers
            );
            if ($the_exception !== null) {
                throw $the_exception;
            }
        } else {
            $affected = $this->affected_rows;
            __phuzz_write_query_success(
                'mysqli::query',
                $event_seq,
                $query,
                null,
                null,
                $affected,
                $duration_ms,
                $timestamp,
                $markers
            );
        }

        return $result;
    },
    true
);
