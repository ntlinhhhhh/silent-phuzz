import os
import random
import json
import gzip
import time
import threading
import warnings
import sys


def fuzz_open(path, mode="r"):
    if os.environ["FUZZER_COMPRESS"] == "1":
        return gzip.open(path, mode + "t")
    else:
        return open(path, mode)

def string_is_number(string):
    # checks if string is a number
    try:
        int(string)
        return True
    except ValueError:
        return False


def sort_by_sublist_length(list_of_lists):
    return sorted(list_of_lists, key=lambda x: (len(x), x[0]["name"], x[0]['value']), reverse=True)


def strip_quotes(strings):
    return [string.strip('"\'') for string in strings]


def get_file_path(file_name):
    return f"{os.path.dirname(os.path.realpath(__file__))}{file_name}"


def get_path_growth(paths_previous, paths_current):
    return len(paths_current) - len(paths_previous)


def coverage_report_has_functions(coverage_report_for_file):
    return "functions" in coverage_report_for_file and type(coverage_report_for_file["functions"]) == dict


def coverage_report_has_lines(coverage_report_for_file):
    return "lines" in coverage_report_for_file and type(coverage_report_for_file["lines"]) == dict


def get_executed_lines(coverage_report, file_name):
    for x in coverage_report[file_name]["lines"].keys():
        if coverage_report[file_name]["lines"][x] > 0:
            yield x

def stringify_hit_or_line(file, path):
    try:
        return f'{file}::::{"_".join([str(x) for x in path["path"]])}'
    except:
        return f'{file}::::{"_".join([str(x) for x in path["lines"]])}'


def stringify_hit_paths(hit_paths):
    return [
        stringify_hit_or_line(file, hit)
        for path in hit_paths
        for file in path
        for hit in path[file]
    ]

def lines_count_dict(hit_paths):
    d = {}
    for path in hit_paths:
        for file in path:
            for hit in path[file]:
                for hp in hit['path']:
                    key = f"{file}:{hp}"
                    if not key in d:
                        d[key] = 1
                    else:
                        d[key] += 1
    return d


def add_paths(paths, new_paths):
    return paths + [p for p in new_paths if p not in paths]


def get_executed_paths(coverage_report, file_name, function):
    for x in coverage_report[file_name]["functions"][function]["paths"]:
        if x["hit"] > 0:
            yield x


def extract_hit_paths(coverage_report):
    hit_paths = []
    for file in coverage_report.keys():
        if "__fuzzer__" in file:
            continue
        if file == "__time__":
            continue

        # XDEBUG coverage
        if coverage_report_has_functions(coverage_report[file]):
            for function in coverage_report[file]["functions"]:
                paths = list(get_executed_paths(coverage_report, file, function))
                hit_paths.append({file: paths})
        elif coverage_report_has_lines(coverage_report[file]):
            lines = list(get_executed_lines(coverage_report, file))
            paths = [{"lines": [int(x) for x in lines], "hit": 1}]
            hit_paths.append({file: paths})

        # PCOV coverage
        else:
            #       x = (line_no, hit_info) -> (49, -1|1) -> We only want hit lines with 1
            lines = sorted(map(lambda y: y[0], filter(lambda x: x[1] > 0, coverage_report[file].items())))
            paths = [{"lines": [int(x) for x in lines], "hit":1 }]
            hit_paths.append({file: paths})

    return hit_paths


def sort_by_length(list_of_dicts):
    return sorted(list_of_dicts, key=lambda x: len(x))

def read_har_file(file_path):
    with fuzz_open(file_path, "r") as f:
        return json.load(f)


def parse_requests(data):
    requests = data["log"]["entries"]
    request_info = []
    for request in requests:
        method = request['request']['method']
        cookies = request["request"]["cookies"]
        query_string = request["request"]["queryString"]
        headers = request["request"]["headers"]
        try:
            payload = request["request"]["postData"]["text"]
        except KeyError:
            payload = []
        try:
            form_data = request["request"]["postData"]["params"]
        except KeyError:
            form_data = []
        info = {
            "url": request["request"]["url"],
            'method': method,
            "cookies": cookies,
            "query_string": query_string,
            "headers": headers,
            "payload": payload,
            "form_data": form_data,
        }
        request_info.append(info)
    return request_info


def filter_requests_by_domain(requests, domain):
    return [
        request
        for request in requests
        if domain in request["url"]
    ]


def extract_input_vectors_from_har(file_path, domain=None):
    data = read_har_file(file_path)
    requests = parse_requests(data)
    if domain:
        return filter_requests_by_domain(requests, domain)
    else:
        return requests

class TraceIdGenerator:
    CHARS = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    BASE = 62
    EPOCH = 1767225600          # 01/01/2026 00:00:00 UTC
    MAX_DELTA = BASE ** 5       # 62^5 = 916,132,832 seconds (~29 years)
    MAX_COUNTER = BASE ** 4     # 62^4 = 14,776,336 requests/sec/node

    def __init__(self, node_id: int):
        if not (0 <= node_id < self.BASE):
            warning_msg = (
                f"[WARNING] TraceIdGenerator: Invalid node_id '{node_id}'. "
                f"Must be between 0 and {self.BASE - 1}. Defaulting to node_id=0."
            )
            print(warning_msg, file=sys.stderr)
            warnings.warn(warning_msg, RuntimeWarning)
            node_id = 0

        self.node_id = node_id
        self.counter = 0
        self.last_time = 0
        self._lock = threading.Lock()   # Thread-safe lock for counter increment

    @classmethod
    def encode(cls, num: int) -> str:
        if num == 0:
            return cls.CHARS[0]
        arr = []
        while num:
            num, rem = divmod(num, cls.BASE)
            arr.append(cls.CHARS[rem])
        return ''.join(reversed(arr))

    @classmethod
    def decode(cls, s: str) -> int:
        num = 0
        for ch in s:
            num = num * cls.BASE + cls.CHARS.index(ch)
        return num

    def generate(self) -> str:
        with self._lock:
            now = int(time.time())
            delta = now - self.EPOCH

            # 1. Check Epoch Overflow (> 29 Years)
            if delta >= self.MAX_DELTA:
                err_msg = (
                    f"[CRITICAL WARNING] TraceIdGenerator: Epoch delta ({delta}s) has exceeded "
                    f"the maximum limit of 62^5 ({self.MAX_DELTA}s). "
                    f"Trace IDs are no longer guaranteed to fit within 5 characters for part_time! "
                    f"Please update EPOCH or expand part_time length."
                )
                print(err_msg, file=sys.stderr)
                warnings.warn(err_msg, RuntimeWarning)
            elif delta < 0:
                warn_msg = (
                    f"[WARNING] TraceIdGenerator: System clock is set before EPOCH ({self.EPOCH}). "
                    f"Negative delta encountered!"
                )
                print(warn_msg, file=sys.stderr)
                delta = 0

            # 2. Reset / Increment Counter
            if now == self.last_time:
                self.counter += 1
                # Check Counter Collision/Overflow (Over 14.77 Million requests/second)
                if self.counter >= self.MAX_COUNTER:
                    collision_warn = (
                        f"[WARNING] TraceIdGenerator: Counter overflow detected on Node {self.node_id}! "
                        f"Counter reached {self.counter} (>= 62^4) within the same second ({now}). "
                        f"Counter is wrapping around to 0. ID collision risk elevated for this second!"
                    )
                    print(collision_warn, file=sys.stderr)
                    warnings.warn(collision_warn, RuntimeWarning)
                    self.counter = 0
            else:
                self.last_time = now
                self.counter = 0

            part_node = self.encode(self.node_id)[-1]
            part_time = self.encode(delta).zfill(5)
            part_counter = self.encode(self.counter).zfill(4)

            return part_node + part_time + part_counter