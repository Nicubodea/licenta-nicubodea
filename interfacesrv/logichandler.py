from dllcomm import *
from dbcomm import *
from httpinterface import *

class LogicHandler:
    def marshall_alert(self, alert):
        instructions = []
        attacker = Module(alert['attacker_name'], alert['attacker_start'], alert['attacker_end'])
        victim = Module(alert['victim_name'], alert['victim_start'], alert['victim_end'])

        for instrux in alert['instructions']:
            instructions.append(Instruction(instrux['mnemonic'], instrux['text'], instrux['length']))
        alert_event = ModuleAlertEvent(attacker, victim, alert['rip'], alert['address'], alert['process_name'], alert['pid'], instructions, alert['action'], alert['functionname'], alert['protection'])

        return alert_event

    def __init__(self):
        self.init_db()
        self.init_http()
        self.init_dll()
        self.init_exceptions()
        self.init_processes()
        self.init_blocked_dlls()

    def init_dll(self):
        self.dh = DllHandler()
        self.dh.subscribe(self.new_event)
        self.dh.start_listening()

    def init_db(self):
        self.db = DBHandler()
        self.db.complete_all_timelines()
        self.session = self.db.get_current_session()

    def init_http(self):
        t = threading.Thread(target=self.really_init_http)
        t.start()


    def really_init_http(self):
        server_class = HTTPServer

        def handler(*args):
            HttpServ(self, *args)

        httpd = server_class(('', 80), handler)

        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass
        httpd.server_close()
        pass

    def init_exceptions(self):
        excs = self.db.get_all_exceptions()
        for exc in excs:
            marshalled = self.marshall_alert(exc['alert'])
            m = Marshaller()
            self.dh.add_alert_exception(m.from_py_to_evt(marshalled))

    def init_processes(self):
        procs = self.db.get_all_protected_processes()
        for proc in procs:
            self.dh.add_protection_process(bytes(proc['processname'], 'utf-8'), proc['mask'])

    def init_blocked_dlls(self):
        pass

    def get_protection_for_module(self, name, protection):
        try:
            mask = {
                "\\Windows\\System32\\ntdll.dll": 1,
                "\\Windows\\System32\\kernel32.dll": 2,
                "\\Windows\\System32\\KernelBase.dll": 4,
            }

            return (mask[name] & protection) != 0
        except:
            return False

    def inject_dll_in_process(self, pid):
        self.dh.inject_dll(pid)

    def new_event(self, evt, obj):

        if evt.event_type == "Process Create":
            print("creating process")
            self.db.create_new_timeline(evt.name, evt.pid, self.session, evt.protection != 0)
            self.db.create_new_process_event(evt.name, evt.pid, evt.cr3, evt.eprocess, evt.protection, self.db.get_timeline_id_for_event(evt.pid))

        elif evt.event_type == "Process Terminate":
            print("terminating process")
            self.db.create_terminate_process_event(evt.name, evt.pid, evt.cr3, evt.eprocess, evt.protection,
                                             self.db.get_timeline_id_for_event(evt.pid))
            self.db.complete_timeline(self.db.get_timeline_id_for_event(evt.pid))

        elif evt.event_type == "Module Load":
            print("module loaded", evt.module.name)
            protected = self.get_protection_for_module(evt.module.name, evt.protection)
            self.db.create_module_load_event(evt.module.name, evt.module.start, evt.module.end, evt.processname, evt.pid, protected, self.db.get_timeline_id_for_event(evt.pid))
            if (evt.protection & 0x20) != 0 and evt.module.name == "\\Windows\\System32\\KernelBase.dll":
                self.inject_dll_in_process(evt.pid)

        elif evt.event_type == "Module Unload":
            print("module unloaded")
            protected = self.get_protection_for_module(evt.module.name, evt.protection)
            self.db.create_module_unload_event(evt.module.name, evt.module.start, evt.module.end, evt.processname,
                                             evt.pid, protected, self.db.get_timeline_id_for_event(evt.pid))
        elif evt.event_type == "Module Alert":
            print("module alert")
            id = self.db.create_module_alert_event(evt.attacker.name, evt.attacker.start, evt.attacker.end, evt.victim.name, evt.victim.start, evt.victim.end, evt.processname, evt.pid, evt.rip, evt.address, evt.func_name, evt.action, evt.protection, self.db.get_timeline_id_for_event(evt.pid))
            for instrux in evt.instructions:
                self.db.create_instruction(instrux.mnemonic, instrux.instruction, instrux.length, id)

            self.db.create_new_alert_timeline(id, self.session)


    def add_new_process(self, proc, mask):
        for cproc in self.db.get_all_protected_processes():
            if cproc['processname'] == proc:
                self.change_process(proc, mask)
                return
        self.db.create_protected_process(proc, mask)
        self.dh.add_protection_process(bytes(proc, 'utf-8'), mask)

    def remove_process(self, proc):
        self.db.remove_protected_process(proc)
        self.dh.add_protection_process(bytes(proc, 'utf-8'), 0)

    def change_process(self, proc, mask):
        self.db.change_protected_process(proc, mask)
        self.dh.add_protection_process(bytes(proc, 'utf-8'), mask)


    def add_exception(self, alert_id):
        self.db.create_exception(alert_id)
        alert = self.db.get_alert_by_alert_id(alert_id)
        m = Marshaller()
        self.dh.add_alert_exception(m.from_py_to_evt(self.marshall_alert(alert)))

    def remove_exception(self, exception_id):
        self.db.remove_exception(exception_id)

    def add_blocked_dll(self, dll_name):
        for dll in self.db.get_all_blocked_dlls():
            if dll['dll_name'] == dll_name:
                raise Exception("DLL is already in list!")

        self.db.create_blocked_dll(dll_name)

    def remove_blocked_dll(self, dll_name):
        self.db.removed_blocked_dll(dll_name)

    def print_timelines(self):
        print(self.db.get_all_timelines_grouped_by_session())

    def print_alert_timelines(self):
        print(self.db.get_all_alert_timelines_grouped_by_session())

    def print_one_timeline(self, id):
        print(self.db.get_timeline(id))

    def print_one_alert_timeline(self, id):
        print(self.db.get_alert_timeline(id))