from http.server import BaseHTTPRequestHandler,HTTPServer

import json
import cgi
from urllib.parse import urlparse
from dbcomm import DBHandler

class HttpServ(BaseHTTPRequestHandler):

    def __init__(self, logic_handler,*args):
        self.logic_handler = logic_handler
        BaseHTTPRequestHandler.__init__(self, *args)

    def not_found(self):
        self.send_response(404)
        self.send_header("Content-type", "text/html")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(b"404 - not found!")

    def init_dbd(self, dbd):
        self.dbd = DBHandler()

    def get_response_message(self, status, key, key_text):
        message = {}
        message["status"] = status
        try:
            message[key] = str(key_text, 'utf-8')
        except:
            message[key] = key_text
        return message


    def send_error_with_reason(self, reason):
        self.send_response(400)
        self.send_header("Content-type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        message = self.get_response_message("Error", "reason", reason)
        self.wfile.write(json.dumps(message).encode('utf-8'))
        return


    def send_success_with_key(self, key, key_text):
        self.send_response(200)
        self.send_header("Content-type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        message = self.get_response_message("Success", key, key_text)
        self.wfile.write(json.dumps(message).encode('utf-8'))
        return

    def handle_get_timeline(self, id):
        dbd = DBHandler()
        self.send_success_with_key("answer", dbd.get_timeline(id))

    def handle_get_timelines(self):
        dbd = DBHandler()
        self.send_success_with_key("answer", dbd.get_all_timelines_grouped_by_session())

    def handle_get_alert_timeline(self, id):
        dbd = DBHandler()
        self.send_success_with_key("answer", dbd.get_alert_timeline(id))

    def handle_get_alert_timelines(self):
        dbd = DBHandler()
        self.send_success_with_key("answer", dbd.get_all_alert_timelines_grouped_by_session())

    def handle_get_protected_processes(self):
        dbd = DBHandler()
        self.send_success_with_key("answer", dbd.get_all_protected_processes())

    def handle_get_exceptions(self):
        dbd = DBHandler()
        self.send_success_with_key("answer", dbd.get_all_exceptions())

    def handle_get_blocked_dlls(self):
        dbd = DBHandler()
        self.send_success_with_key("answer", dbd.get_all_blocked_dlls())

    def test_something(self):
        try:
            self.logic_handler.add_exception(9)
            self.send_success_with_key("answer", "")
        except Exception as e:
            self.send_error_with_reason(str(e))

    def do_GET(self):
        query = urlparse(self.path).query
        path = urlparse(self.path).path
        try:
            query_components = dict(qc.split("=") for qc in query.split("&"))
        except:
            query_components = {}

        try:
            if path == "/get_timelines":
                return self.handle_get_timelines()

            if path == "/get_timeline":
                return self.handle_get_timeline(query_components["id"])

            if path == "/get_alert":
                return self.handle_get_alert_timeline(query_components["id"])

            if path == "/get_alerts":
                return self.handle_get_alert_timelines()

            if path == "/get_protected":
                return self.handle_get_protected_processes()

            if path == "/get_exceptions":
                return self.handle_get_exceptions()

            if path == "/get_blocked_dlls":
                return self.handle_get_blocked_dlls()

            #if path == "/test":
            #    return self.test_something()

            raise Exception("Not found")

        except:
            self.not_found()

    def post_new_prot_proc(self, postvars):
        try:
            procname = postvars[b"process"][0].decode('utf-8')
            mask = int(postvars[b"mask"][0].decode('utf-8'))

            self.logic_handler.add_new_process(procname, mask)

            self.send_success_with_key("answer", "")
        except Exception as e:
            self.send_error_with_reason(str(e))

    def post_delete_prot_proc(self, postvars):
        try:
            procname = postvars[b"process"][0].decode('utf-8')

            self.logic_handler.remove_process(procname)

            self.send_success_with_key("answer", "")
        except Exception as e:
            self.send_error_with_reason(str(e))

    def post_change_prot_proc(self, postvars):
        try:
            procname = postvars[b"process"][0].decode('utf-8')
            mask = int(postvars[b"mask"][0].decode('utf-8'))

            self.logic_handler.change_process(procname, mask)

            self.send_success_with_key("answer", "")

        except Exception as e:
            self.send_error_with_reason(str(e))

    def post_add_exception(self, postvars):
        try:
            alert_id = int(postvars[b"alert_id"][0].decode('utf-8'))

            self.logic_handler.add_exception(alert_id)

            self.send_success_with_key("answer", "")
        except Exception as e:
            self.send_error_with_reason(str(e))

    def post_remove_exception(self, postvars):
        try:
            alert_id = int(postvars[b"exception_id"][0].decode('utf-8'))

            self.logic_handler.remove_exception(alert_id)

            self.send_success_with_key("answer", "")
        except Exception as e:
            self.send_error_with_reason(str(e))

    def post_add_blocked_dll(self, postvars):
        try:
            dll_name =  postvars[b"dll_name"][0].decode('utf-8')

            self.logic_handler.add_blocked_dll(dll_name)

            self.send_success_with_key("answer", "")
        except Exception as e:
            self.send_error_with_reason(str(e))

    def post_remove_blocked_dll(self, postvars):
        try:
            dll_name = postvars[b"dll_name"][0].decode('utf-8')

            self.logic_handler.remove_blocked_dll(dll_name)

            self.send_success_with_key("answer", "")
        except Exception as e:
            self.send_error_with_reason(str(e))

    def do_POST(self):
        ctype, pdict = cgi.parse_header(self.headers['Content-type'])
        if ctype == 'multipart/form-data':
            postvars = cgi.parse_multipart(self.rfile, pdict)
        elif ctype == 'application/x-www-form-urlencoded':
            length = int(self.headers['Content-length'])
            postvars = cgi.parse_qs(self.rfile.read(length), keep_blank_values=1)
        else:
            postvars = {}

        try:
            if self.path == "/add_prot_proc":
                return self.post_new_prot_proc(postvars)
            elif self.path == "/remove_prot_proc":
                return self.post_delete_prot_proc(postvars)
            elif self.path == "/change_prot_proc":
                return self.post_change_prot_proc(postvars)
            elif self.path == "/add_exception":
                return self.post_add_exception(postvars)
            elif self.path == "/remove_exception":
                return self.post_remove_exception(postvars)
            elif self.path == "/new_blocked_dll":
                return self.post_add_blocked_dll(postvars)
            elif self.path == "/remove_blocked_dll":
                return self.post_remove_blocked_dll(postvars)

            raise Exception("Not found")
        except:
            self.not_found()