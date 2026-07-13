import html
import os

import bleach
import esprima
import urllib.parse as urlparse
import json
from bs4 import BeautifulSoup, element
from difflib import SequenceMatcher
from utils import fuzz_open
import sqlglot
from sqlglot import exp



class VulnCheck():
    NAME = "Example"

    def check(self, candidate):
        return False



# Code for this class taken from https://github.com/ovanr/webFuzz/blob/v1.2.0/webFuzz/webFuzz/
class WebFuzzXSSVulnCheck(VulnCheck):
    NAME = "WebFuzzXSSVulnCheck"
    CONFIDENCE_NONE = 0
    CONFIDENCE_LOW = 1
    CONFIDENCE_HIGH = 2

    URLATTRIBUTES = [
        "action",
        "cite",
        "data",
        "formaction",
        "href",
        "longdesc",
        "manifest",
        "poster",
        "src"
    ]

    FLAGGED_ELEMENTS = {
        CONFIDENCE_NONE: {},
        CONFIDENCE_LOW: {},
        CONFIDENCE_HIGH: {},
    }


    def _webfuzz_misc_longest_str_match(self, haystack, needle):
        # https://github.com/ovanr/webFuzz/blob/v1.2.0/webFuzz/webFuzz/misc.py#L101
        match = SequenceMatcher(None, haystack, needle)
        (_,__,size) = match.find_longest_match(0, len(haystack), 0, len(needle))
        return size


    def _webfuzz_xss_precheck(self, candidate):
        # Taken from WebFuzz
        # https://github.com/ovanr/webFuzz/blob/v1.2.0/webFuzz/webFuzz/detector.py#L149

        raw_html = candidate.response.text
        if self._webfuzz_misc_longest_str_match(raw_html, "0xdeadbeef") >= 5:
            return True
        else:
            return False

    def _webfuzz_xss_record_response(self, candidate, confidence, id_, elem_type, value):

        if confidence == WebFuzzXSSVulnCheck.CONFIDENCE_NONE:
            return

        candidate_url = candidate.response.url

        if candidate_url not in WebFuzzXSSVulnCheck.FLAGGED_ELEMENTS[confidence]:
            WebFuzzXSSVulnCheck.FLAGGED_ELEMENTS[confidence][candidate_url] = set()

        if id_ not in WebFuzzXSSVulnCheck.FLAGGED_ELEMENTS[confidence][candidate_url]:

            if not WebFuzzXSSVulnCheck.FLAGGED_ELEMENTS[WebFuzzXSSVulnCheck.CONFIDENCE_HIGH].get(candidate_url, []):
                if confidence == WebFuzzXSSVulnCheck.CONFIDENCE_HIGH:
                    self.xss_count += 1

            WebFuzzXSSVulnCheck.FLAGGED_ELEMENTS[confidence][candidate_url].add(id_)

            # if node.is_mutated:
            #     # reward parent node with a sink found
            #     node.parent_request.has_sinks = True


    def _webfuzz_xss_should_analyze(self, id_, url, elem_content):
        if id_ not in WebFuzzXSSVulnCheck.FLAGGED_ELEMENTS[WebFuzzXSSVulnCheck.CONFIDENCE_HIGH].get(url, []) and \
            self._webfuzz_misc_longest_str_match(elem_content, "0xdeadbeef") >= 5:
            return True
        else:
            return False

    def _webfuzz_xss_js_ast_traversal(self, node):
        confidence = WebFuzzXSSVulnCheck.CONFIDENCE_NONE

        if type(node) == list:
            for stmt in node:
                res = self._webfuzz_xss_js_ast_traversal(stmt)
                if res == WebFuzzXSSVulnCheck.CONFIDENCE_HIGH:
                    return WebFuzzXSSVulnCheck.CONFIDENCE_HIGH
                else:
                    confidence = max(res, confidence)

        elif 'esprima.nodes.CallExpression' in str(type(node)):
             if node.callee.name in ["alert", "prompt", "confirm"]:

                res = self._webfuzz_xss_js_ast_traversal(node.arguments)
                if res > WebFuzzXSSVulnCheck.CONFIDENCE_NONE:
                    # 0xdeadbeef found in one of its arguments
                    return WebFuzzXSSVulnCheck.CONFIDENCE_HIGH
                else:
                    confidence = max(res, confidence)

        elif 'esprima.nodes.TaggedTemplateExpression' in str(type(node)):
            if node.quasi.type == 'TemplateLiteral' and \
               node.tag.name in ["alert", "prompt", "confirm"]:

                res = self._webfuzz_xss_js_ast_traversal(node.quasi.quasis)
                if res > WebFuzzXSSVulnCheck.CONFIDENCE_NONE:
                    # 0xdeadbeef found in one of its arguments
                    return WebFuzzXSSVulnCheck.CONFIDENCE_HIGH
                else:
                    confidence = max(res, confidence)

        if "esprima.nodes" in str(type(node)):
            for attr in dir(node):
                res = self._webfuzz_xss_js_ast_traversal(getattr(node, attr))
                if res == WebFuzzXSSVulnCheck.CONFIDENCE_HIGH:
                    return WebFuzzXSSVulnCheck.CONFIDENCE_HIGH
                else:
                    confidence = max(res, confidence)

        if type(node) == str:
            if longest_str_match(node, "0xdeadbeef") >= 5:
                confidence = max(WebFuzzXSSVulnCheck.CONFIDENCE_LOW, confidence)

        return confidence

    def _webfuzz_xss_handle_script(self, elem_content):
        try:
            script = esprima.parseScript(elem_content)
            return self._webfuzz_xss_js_ast_traversal(script.body)
        except:
            # fallback to weak method
            if self._webfuzz_misc_longest_str_match(elem_content, "0xdeadbeef") >= 5:
                return WebFuzzXSSVulnCheck.CONFIDENCE_LOW
            
            return WebFuzzXSSVulnCheck.CONFIDENCE_NONE

    def _webfuzz_xss_handle_attr(self, attr_name, attr_content):
        result = WebFuzzXSSVulnCheck.CONFIDENCE_LOW

        if attr_name.lower() in WebFuzzXSSVulnCheck.URLATTRIBUTES and \
           attr_content[:11].lower() == "javascript:":
            # strip leading javascript
            attr_content = attr_content[11:]
            result = self._webfuzz_xss_handle_script(attr_content)

        elif attr_name[:2] == "on":
            result = self._webfuzz_xss_handle_script(attr_content)

        return result

    def _webfuzz_xss_scanner(self, candidate):
        # Taken from Webfuzz
        # https://github.com/ovanr/webFuzz/blob/4e8da2aa80f932cc0f7c05212620b24654a3092c/webFuzz/webFuzz/detector.py#L154

        raw_html = candidate.response.text
        bsoup = BeautifulSoup(raw_html, "html.parser")
        confidence = WebFuzzXSSVulnCheck.CONFIDENCE_NONE

        for elem in bsoup.find_all():
            if type(elem) != element.Tag:
                continue

            id_ = elem.name + "/" + elem.attrs.get('id', "")

            if elem.name == "script":
                if not self._webfuzz_xss_should_analyze(id_, candidate.response.url, elem.text):
                    continue

                result = self._webfuzz_xss_handle_script(elem.text)

                self._webfuzz_xss_record_response(candidate, result, id_, elem_type="Script", value=elem.text)

                confidence = max(result, confidence)

            for (attr_name, attr_value) in elem.attrs.items():
                param_id = id_ + "/" + attr_name
                if not self._webfuzz_xss_should_analyze(param_id, candidate.response.url, attr_value):
                    continue

                result = self._webfuzz_xss_handle_attr(attr_name, attr_value)
                self._webfuzz_xss_record_response(candidate, result, param_id, elem_type=f"Attribute {attr_name}", value=attr_value)

                confidence = max(result, confidence)

        return confidence

    def check(self, candidate):
        if not candidate.response:
            return False

        # Taken from WebFuzz
        # https://github.com/ovanr/webFuzz/blob/v1.2.0/webFuzz/webFuzz/worker.py#L126
        if not self._webfuzz_xss_precheck(candidate):
            return False

        if self._webfuzz_xss_scanner(candidate) > WebFuzzXSSVulnCheck.CONFIDENCE_NONE:
            return True

        return False


class XSSVulnCheck(VulnCheck):
    NAME = "XSS"

    def check(self, candidate):
        if not candidate.response:
            return False
        for param_type in ['query_params', 'body_params', 'headers', 'cookies']:
            for param in candidate.fuzz_params[param_type].items():
                if html.unescape(bleach.clean(param[1], strip=True)) != param[1]:
                    if candidate.response.text.find(param[1]) != -1:
                        candidate.vulns.append(self.NAME)
                        return True
        return False


class SQLiVulnCheck(VulnCheck):
    NAME = "SQLi"

    def __init__(self, mysql_errors_folder):
        self.mysql_errors_folder = mysql_errors_folder

    def check(self, candidate):
        sqli_file = os.path.join(
            self.mysql_errors_folder, f"{candidate.coverage_id}.json"
        )
        if os.path.isfile(sqli_file):
            return True
        return False

class ParamBasedSQLiVulnCheck(VulnCheck):
    NAME = "SQLi"

    def __init__(self, mysql_errors_folder):
        self.mysql_errors_folder = mysql_errors_folder

    def check(self, candidate):
        sqli_file = os.path.join(
            self.mysql_errors_folder, f"{candidate.coverage_id}.json"
        )
        if not os.path.isfile(sqli_file):
            return False

        for line in fuzz_open(sqli_file):
            if not line.strip():
                continue
            error = json.loads(line)
            for error_param in error['params']:
                if not error_param:
                    continue
                for vuln_type in candidate.fuzz_params.keys():
                    for pkey, pval in candidate.fuzz_params[vuln_type].items():
                        if pval in error_param:
                            return True
        return False


class SilentSQLiVulnCheck(VulnCheck):
    NAME = "Silent SQLi"

    def __init__(self, mysql_query_events_folder):
        self.mysql_query_events_folder = mysql_query_events_folder
        self.honey_columns = {"phuzz_canary", "canary"}
        self.delay_functions = {"sleep", "benchmark", "pg_sleep"}
        self.sensor_tables = {"__phuzz_sensor_insert", "__phuzz_sensor_update", "__phuzz_sensor_delete", "phuzz_sensor"}

    def check(self, candidate):
        if not self.mysql_query_events_folder:
            return False
        event_file = os.path.join(
            self.mysql_query_events_folder, f"{candidate.coverage_id}.json"
        )
        if not os.path.isfile(event_file):
            return False

        # Thu thập toàn bộ các giá trị đầu vào mà fuzzer đã chèn/đột biến
        fuzz_values = []
        if hasattr(candidate, 'fuzz_params') and candidate.fuzz_params:
            for category in candidate.fuzz_params.values():
                if isinstance(category, dict):
                    for val in category.values():
                        fuzz_values.append(str(val).lower())

        for line in fuzz_open(event_file):
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except Exception:
                continue

            query = event.get("query", "")
            if not query:
                continue

            # 1. AST Parsing
            try:
                ast = sqlglot.parse_one(query)
            except Exception:
                # If syntax error but execution was successful, could indicate SQLi bypass/anomaly,
                # but we'll focus on successfully parsed ASTs first.
                continue

            # 2. Check for Time-Based functions in AST (e.g. sleep, benchmark, pg_sleep)
            # Chỉ ghi nhận lỗi nếu Fuzzer thực sự gửi payload chứa hàm delay
            for func in ast.find_all(exp.Anonymous):
                func_name = func.name.lower()
                if func_name in self.delay_functions:
                    if any(func_name in val for val in fuzz_values):
                        candidate.vulns.append(f"{self.NAME}_TimeBased")
                        return True
            for func in ast.find_all(exp.Func):
                func_name = func.sql_name().lower()
                if func_name in self.delay_functions:
                    if any(func_name in val for val in fuzz_values):
                        candidate.vulns.append(f"{self.NAME}_TimeBased")
                        return True

            # 3. Check for Honey Column Accesses
            # Chỉ ghi nhận lỗi nếu Fuzzer thực sự gửi payload chứa tên cột bẫy
            for col in ast.find_all(exp.Column):
                col_name = col.name.lower()
                if col_name in self.honey_columns:
                    if any(col_name in val for val in fuzz_values):
                        candidate.vulns.append(f"{self.NAME}_HoneyColumn")
                        return True

            # 4. Check for Sensor Table Accesses
            # Chỉ ghi nhận lỗi nếu Fuzzer thực sự gửi payload chứa tên bảng cảm biến
            for table in ast.find_all(exp.Table):
                table_name = table.name.lower()
                if table_name in self.sensor_tables:
                    if any(table_name in val for val in fuzz_values):
                        candidate.vulns.append(f"{self.NAME}_SensorTable")
                        return True

            # 5. Check for DDL operations (CREATE, ALTER, DROP)
            # Chỉ ghi nhận lỗi nếu Fuzzer thực sự gửi payload chứa từ khóa DDL cấu trúc
            ddl_classes = [exp.Create, exp.Drop, exp.Alter]
            if hasattr(exp, 'AlterTable'):
                ddl_classes.append(getattr(exp, 'AlterTable'))
            if isinstance(ast, tuple(ddl_classes)):
                if any(kw in val for val in fuzz_values for kw in ['create', 'drop', 'alter']):
                    candidate.vulns.append(f"{self.NAME}_DDL")
                    return True

            # 6. Check if query execution latency suggests Sleep injection or anomalous delay
            execution_time = event.get("execution_time", 0)
            if execution_time > 2.0:  # Any query taking > 2 seconds in a controlled lab fuzzing environment is anomalous
                # Let's confirm if sleep or delay function string is in raw query as fallback
                query_lower = query.lower()
                for df in self.delay_functions:
                    if df in query_lower:
                        if any(df in val for val in fuzz_values):
                            candidate.vulns.append(f"{self.NAME}_TimeBasedAnomalous")
                            return True

        return False

class CommandInjectionVulnCheck(VulnCheck):
    NAME = "CommandInjection"

    def __init__(self, shell_errors_folder):
        self.shell_errors_folder = shell_errors_folder

    def check(self, candidate):
        cmd_injection_file = os.path.join(
            self.shell_errors_folder, f"{candidate.coverage_id}.json"
        )
        if os.path.isfile(cmd_injection_file):
            return True
        return False

class ParamBasedCommandInjectionVulnCheck(VulnCheck):
    NAME = "CommandInjection"

    def __init__(self, shell_errors_folder):
        self.shell_errors_folder = shell_errors_folder

    def check(self, candidate):
        cmd_injection_file = os.path.join(
            self.shell_errors_folder, f"{candidate.coverage_id}.json"
        )
        if not os.path.isfile(cmd_injection_file):
            return False

        for line in fuzz_open(cmd_injection_file):
            if not line.strip():
                continue
            error = json.loads(line)
            for error_param in error['params']:
                if not error_param:
                    continue
                for vuln_type in candidate.fuzz_params.keys():
                    for pkey, pval in candidate.fuzz_params[vuln_type].items():
                        if pval in error_param:
                            return True
        return False

class UnserializeVulnCheck(VulnCheck):
    NAME = "Unserialize"

    def __init__(self, unserialize_errors_folder):
        self.unserialize_errors_folder = unserialize_errors_folder

    def check(self, candidate):
        unserialize_file = os.path.join(
            self.unserialize_errors_folder, f"{candidate.coverage_id}.json"
        )
        if os.path.isfile(unserialize_file):
            return True
        return False

class ParamBasedUnserializeVulnCheck(VulnCheck):
    NAME = "Unserialize"

    def __init__(self, unserialize_errors_folder):
        self.unserialize_errors_folder = unserialize_errors_folder

    def check(self, candidate):
        unserialize_file = os.path.join(
            self.unserialize_errors_folder, f"{candidate.coverage_id}.json"
        )
        if not os.path.isfile(unserialize_file):
            return False

        for line in fuzz_open(unserialize_file):
            if not line.strip():
                continue
            error = json.loads(line)
            for error_param in error['params']:
                if not error_param:
                    continue
                for vuln_type in candidate.fuzz_params.keys():
                    for pkey, pval in candidate.fuzz_params[vuln_type].items():
                        if pval in error_param:
                            return True
        return False

class PathTraversalVulnCheck(VulnCheck):
    NAME = "PathTraversal"

    def __init__(self, pathtraversal_errors_folder):
        self.pathtraversal_errors_folder = pathtraversal_errors_folder

    def check(self, candidate):
        pathtraversal_file = os.path.join(
            self.pathtraversal_errors_folder, f"{candidate.coverage_id}.json"
        )
        if os.path.isfile(pathtraversal_file):
            return True
        return False

class ParamBasedPathTraversalVulnCheck(VulnCheck):
    NAME = "PathTraversal"

    def __init__(self, pathtraversal_errors_folder):
        self.pathtraversal_errors_folder = pathtraversal_errors_folder

    def check(self, candidate):
        pathtraversal_file = os.path.join(
            self.pathtraversal_errors_folder, f"{candidate.coverage_id}.json"
        )
        if not os.path.isfile(pathtraversal_file):
            return False

        for line in fuzz_open(pathtraversal_file):
            if not line.strip():
                continue
            error = json.loads(line)
            for error_param in error['params']:
                if not error_param:
                    continue
                for vuln_type in candidate.fuzz_params.keys():
                    for pkey, pval in candidate.fuzz_params[vuln_type].items():
                        if pval in error_param:
                            return True
        return False

class WebPathBasedPathTraversalVulnCheck(VulnCheck):
    NAME = "PathTraversal"

    def __init__(self, pathtraversal_errors_folder):
        self.pathtraversal_errors_folder = pathtraversal_errors_folder
        self.web_paths = []
        with open(os.path.join("/shared-tmpfs", "web-paths.txt")) as f:
            for path in f:
                self.web_paths.append(path.strip())

    def check(self, candidate):
        pathtraversal_file = os.path.join(
            self.pathtraversal_errors_folder, f"{candidate.coverage_id}.json"
        )
        if not os.path.isfile(pathtraversal_file):
            return False

        for line in fuzz_open(pathtraversal_file):
            if not line.strip():
                continue
            error = json.loads(line)
            for error_param in error['params']:
                if not error_param:
                    continue
                if error_param in self.web_paths:
                    continue
                for vuln_type in candidate.fuzz_params.keys():
                    for pkey, pval in candidate.fuzz_params[vuln_type].items():
                        if pval in error_param:
                            return True
        return False

class OpenRedirectVulnCheck(VulnCheck):
    NAME = "OpenRedirect"

    def check(self, candidate):
        if candidate.response is None:
            return False

        respones = candidate.response.history if candidate.response.history else [candidate.response]
        for resp in respones:
            if 300 <= resp.status_code < 400 and 'Location' in resp.headers:
                dest_url = resp.headers['Location']
                dest_url_parts = list(urlparse.urlparse(dest_url))
                for vuln_type in candidate.fuzz_params.keys():
                    for pkey, pval in candidate.fuzz_params[vuln_type].items():
                        pval_parts = list(urlparse.urlparse(pval))
                        if pval == dest_url or pval in dest_url_parts or dest_url_parts == pval_parts:
                            return True
                            # This could be more sophisticated, but should be sufficient for easy open redirects.
        
        return False

class XXEVulnCheck(VulnCheck):
    NAME = "XXE"

    def __init__(self, xxe_errors_folder):
        self.xxe_errors_folder = xxe_errors_folder

    def check(self, candidate):
        xxe_file = os.path.join(
            self.xxe_errors_folder, f"{candidate.coverage_id}.json"
        )
        if os.path.isfile(xxe_file):
            return True
        return False

class ParamBasedXXEVulnCheck(VulnCheck):
    NAME = "XXE"

    def __init__(self, xxe_errors_folder):
        self.xxe_errors_folder = xxe_errors_folder

    def check(self, candidate):
        xxe_file = os.path.join(
            self.xxe_errors_folder, f"{candidate.coverage_id}.json"
        )
        if not os.path.isfile(xxe_file):
            return False

        for line in fuzz_open(xxe_file):
            if not line.strip():
                continue
            error = json.loads(line)
            for error_param in error['params']:
                if not error_param:
                    continue
                for vuln_type in candidate.fuzz_params.keys():
                    for pkey, pval in candidate.fuzz_params[vuln_type].items():
                        if pval in error_param:
                            return True
        return False


class VulnChecker():
    def __init__(self):
        self.vuln_checkers = []

    def vuln_check(self, candidate):
        pass


class DefaultVulnChecker(VulnChecker):
    def __init__(self, mysql_errors_folder=None, mysql_query_events_folder=None, shell_errors_folder=None, unserialize_errors_folder=None, pathtraversal_errors_folder=None, xxe_errors_folder=None):
        super(VulnChecker, self).__init__()
        self.vuln_checkers = [
            # WebFuzzXSSVulnCheck(),
            SQLiVulnCheck(mysql_errors_folder),
            SilentSQLiVulnCheck(mysql_query_events_folder),
            # CommandInjectionVulnCheck(shell_errors_folder),
            # UnserializeVulnCheck(unserialize_errors_folder),
            # PathTraversalVulnCheck(pathtraversal_errors_folder),
            # OpenRedirectVulnCheck(),
            # XXEVulnCheck(xxe_errors_folder)
        ]

    def vuln_check(self, candidate):
        vulns = []
        for vuln_check in self.vuln_checkers:
            if vuln_check.check(candidate):
                vulns.append(vuln_check.NAME)
        return vulns

class SecondOrderSQLiVulnCheck(VulnCheck):
    NAME = "Second-Order SQLi"

    def __init__(self, db_write_events_folder, mysql_errors_folder, 
                 mysql_query_events_folder):
        self.db_write_events_folder = db_write_events_folder
        self.mysql_errors_folder = mysql_errors_folder
        self.mysql_query_events_folder = mysql_query_events_folder

    def check(self, candidate):
        # 1. Quet tat ca cac file log loi co trong thu muc de tim file dang fuzz_*.json
        import glob
        error_files = glob.glob(os.path.join(self.mysql_errors_folder, "fuzz_*.json"))
        query_event_files = glob.glob(os.path.join(self.mysql_query_events_folder, "fuzz_*.json"))
        
        found_vuln = False
        
        # Tap hop tat ca cac file log can kiem tra
        all_logs = []
        for ef in error_files:
            all_logs.append((ef, 'error'))
        for qf in query_event_files:
            all_logs.append((qf, 'query_event'))
            
        for filepath, log_type in all_logs:
            filename = os.path.basename(filepath)
            # Trich xuat trace_id tu ten file (vd: fuzz_12345.json -> fuzz_12345)
            trace_id = filename.replace(".json", "")
            
            sink_errors = []
            sink_query_events = []
            
            if log_type == 'error':
                for line in fuzz_open(filepath):
                    if line.strip():
                        try:
                            sink_errors.append(json.loads(line))
                        except Exception:
                            pass
            else:
                for line in fuzz_open(filepath):
                    if line.strip():
                        try:
                            sink_query_events.append(json.loads(line))
                        except Exception:
                            pass
                            
            if not sink_errors and not sink_query_events:
                continue
                
            # 2. Truy van database lay thong tin nguon (Source) tuong ung voi trace_id nay
            source_url = "unknown"
            source_method = "unknown"
            payload_sample = "unknown"
            
            try:
                import mysql.connector
                conn = mysql.connector.connect(
                    host="db",
                    user="root",
                    password="rootpassword",
                    database="silent_testbed"
                )
                cursor = conn.cursor()
                cursor.execute("SELECT url, method, payload_sample FROM fuzz_history WHERE fuzz_trace_id = %s", (trace_id,))
                row = cursor.fetchone()
                if row:
                    source_url, source_method, payload_sample = row
                cursor.close()
                conn.close()
            except Exception:
                pass
                
            # 3. Kiem tra xem co phai day la payload den tu phien fuzz hien tai khong (tranh trigger nham cua phien cu)
            # Neu url la register hoac billing, thiet lap thong tin attribution cho Candidate
            if source_url != "unknown":
                found_vuln = True
                
                # Xác định loại lỗi
                vuln_type = "Second-Order SQLi_Silent"
                sink_query = ""
                
                if sink_errors:
                    err = sink_errors[0]
                    errstr = err.get('errstr', '').lower()
                    if any(x in errstr for x in ['xpath', 'extractvalue', 'updatexml']):
                        vuln_type = "Second-Order SQLi_ErrorBased_XPath"
                    elif 'syntax error' in errstr or 'you have an error in your sql syntax' in errstr:
                        vuln_type = "Second-Order SQLi_SyntaxError"
                    else:
                        vuln_type = "Second-Order SQLi_ErrorBased"
                    sink_query = str(err.get('params', [err.get('errstr')])[0])
                elif sink_query_events:
                    qe = sink_query_events[0]
                    query = qe.get('query', '').lower()
                    if "sleep" in query or "benchmark" in query:
                        vuln_type = "Second-Order SQLi_TimeBased"
                    elif "sensor" in query:
                        vuln_type = "Second-Order SQLi_SensorTable"
                    elif "canary" in query:
                        vuln_type = "Second-Order SQLi_HoneyColumn"
                    sink_query = qe.get('query', '')
                
                # Lay tham so fuzz trong request cua Source
                fuzz_param = "unknown"
                for ptype, pdata in candidate.fuzz_params.items():
                    if isinstance(pdata, dict) and pdata:
                        fuzz_param = list(pdata.keys())[0]
                        break
                        
                candidate.source_attribution = {
                    'source_endpoint': source_url,
                    'source_method': source_method,
                    'source_parameter': fuzz_param,
                    'source_payload_sent': payload_sample,
                    'sink_endpoint': candidate.http_target,
                    'sink_query': sink_query[:500],
                    'data_flow': f"{source_url} ({source_method}) -> DB -> {candidate.http_target} ({candidate.http_method}) -> SQL Error: {vuln_type}"
                }
                
                if vuln_type not in candidate.vulns:
                    candidate.vulns.append(vuln_type)
                    
                try:
                    os.unlink(filepath)
                except Exception:
                    pass
        return found_vuln
        
#         self.vuln_checkers = [
#             # WebFuzzXSSVulnCheck(),
#             ParamBasedSQLiVulnCheck(mysql_errors_folder),
#             SilentSQLiVulnCheck(mysql_query_events_folder),
#             # ParamBasedCommandInjectionVulnCheck(shell_errors_folder),
#             # ParamBasedUnserializeVulnCheck(unserialize_errors_folder),
#             #ParamBasedPathTraversalVulnCheck(pathtraversal_errors_folder), # This one was used during the main analysis -> it discovered 'fu' in 'functions.php' (Wordpress), which is a false positive. 
#             # WebPathBasedPathTraversalVulnCheck(pathtraversal_errors_folder), # This one ignores existing files, such as functions.php, and should thus report less false positives.
#             # OpenRedirectVulnCheck(),
#             # ParamBasedXXEVulnCheck(xxe_errors_folder)
#         ]

class ParamBasedVulnChecker(DefaultVulnChecker):
    def __init__(self, mysql_errors_folder=None, mysql_query_events_folder=None,
        db_write_events_folder=None,
        shell_errors_folder=None, unserialize_errors_folder=None, 
        pathtraversal_errors_folder=None, xxe_errors_folder=None):
        self.vuln_checkers = [
            ParamBasedSQLiVulnCheck(mysql_errors_folder),
            SilentSQLiVulnCheck(mysql_query_events_folder),
            SecondOrderSQLiVulnCheck(
                db_write_events_folder=db_write_events_folder,
                mysql_errors_folder=mysql_errors_folder,
                mysql_query_events_folder=mysql_query_events_folder
            ),
        ]