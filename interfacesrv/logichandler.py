from dllcomm import *
from dbcomm import *

class LogicHandler:
    def __init__(self):
        self.init_db()
        self.init_http()
        self.init_dll()

    def init_dll(self):
        self.dh = DllHandler()
        self.dh.subscribe(self.new_event)
        self.dh.start_listening()

    def init_db(self):
        self.db = DBHandler()
        self.db.complete_all_timelines()
        self.session = self.db.get_current_session()

    def init_http(self):
        # TODO: http needs DB
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
    def new_event(self, evt, obj):

        if evt.event_type == "Process Create":
            #print("creating process")
            self.db.create_new_timeline(evt.name, evt.pid, self.session, evt.protection != 0)
            self.db.create_new_process_event(evt.name, evt.pid, evt.cr3, evt.eprocess, evt.protection, self.db.get_timeline_id_for_event(evt.pid))

        elif evt.event_type == "Process Terminate":
            #print("terminating process")
            self.db.create_terminate_process_event(evt.name, evt.pid, evt.cr3, evt.eprocess, evt.protection,
                                             self.db.get_timeline_id_for_event(evt.pid))
            self.db.complete_timeline(self.db.get_timeline_id_for_event(evt.pid))

        elif evt.event_type == "Module Load":
            #print("module loaded", evt.module.name)
            protected = self.get_protection_for_module(evt.module.name, evt.protection)
            self.db.create_module_load_event(evt.module.name, evt.module.start, evt.module.end, evt.processname, evt.pid, protected, self.db.get_timeline_id_for_event(evt.pid))

        elif evt.event_type == "Module Unload":
            #print("module unloaded")
            protected = self.get_protection_for_module(evt.module.name, evt.protection)
            self.db.create_module_unload_event(evt.module.name, evt.module.start, evt.module.end, evt.processname,
                                             evt.pid, protected, self.db.get_timeline_id_for_event(evt.pid))
        elif evt.event_type == "Module Alert":
            #print("module alert")
            id = self.db.create_module_alert_event(evt.attacker.name, evt.attacker.start, evt.attacker.end, evt.victim.name, evt.victim.start, evt.victim.end, evt.processname, evt.pid, evt.rip, evt.address, evt.func_name, evt.action, evt.protection, self.db.get_timeline_id_for_event(evt.pid))
            for instrux in evt.instructions:
                self.db.create_instruction(instrux.mnemonic, instrux.instruction, instrux.length, id)

            self.db.create_new_alert_timeline(id, self.session)


    def add_new_process(self, proc, mask):
        self.dh.add_protection_process(proc, mask)

    def add_exception(self, evt):
        self.dh.add_alert_exception(evt)


    def remove_all_current_processes(self):
        pass

    def print_timelines(self):
        print(self.db.get_all_timelines_grouped_by_session())

    def print_alert_timelines(self):
        print(self.db.get_all_alert_timelines_grouped_by_session())

    def print_one_timeline(self, id):
        print(self.db.get_timeline(id))

    def print_one_alert_timeline(self, id):
        print(self.db.get_alert_timeline(id))