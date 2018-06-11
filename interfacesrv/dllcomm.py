from ctypes import *




class EvtProcessCreate(Structure):
    _fields_ = [("Name", c_byte * 16), ("Cr3", c_longlong), ("Pid", c_longlong), ("Eprocess", c_longlong)]


class EvtProcessTerminate(Structure):
    _fields_ = [("Name", c_byte * 16), ("Cr3", c_longlong), ("Pid", c_longlong), ("Eprocess", c_longlong)]


class EvtModule(Structure):
    _fields_ = [("Name", c_byte * 256), ("Start", c_longlong), ("End", c_longlong)]


class EvtModuleLoad(Structure):
    _fields_ = [("Module", EvtModule), ("ProcessName", c_byte * 16), ("Pid", c_longlong)]


class EvtModuleUnload(Structure):
    _fields_ = [("Module", EvtModule), ("ProcessName", c_byte * 16), ("Pid", c_longlong)]


class EvtInstruction(Structure):
    _fields_ = [("Mnemonic", c_short), ("Instruction", c_byte * 128), ("Length", c_int)]


class EvtModuleAlert(Structure):
    _fields_ = [("Attacker", EvtModule),
                ("Victim", EvtModule),
                ("Rip", c_longlong),
                ("Address", c_longlong),
                ("ProcessName", c_byte * 16),
                ("Pid", c_longlong),
                ("Instructions", EvtInstruction * 10),
                ("NumberOfInstructions", c_int),
                ("Action", c_uint),
                ("FunctionName", c_byte*32)]


class EvtListEntry(Structure):
    _fields_ = [("Flink", c_longlong), ("Blink", c_longlong)]


class EvtUnion(Union):
    _fields_ = [("ProcessCreateEvent", EvtProcessCreate),
                ("ProcessTerminateEvent", EvtProcessTerminate),
                ("ModuleLoadEvent", EvtModuleLoad),
                ("ModuleUnloadEvent", EvtModuleUnload),
                ("ModuleAlertEvent", EvtModuleAlert)]


class Evt(Structure):
    _fields_ = [("Link", EvtListEntry), ("EventType", c_uint), ("Protection", c_uint), ("union", EvtUnion)]


class ProcessCreateEvent:
    def __init__(self, name, pid, cr3, eprocess ,protection):
        self.event_type = "Process Create"
        self.name = name
        self.pid = pid
        self.cr3 = cr3
        self.eprocess = eprocess
        self.protection = protection


class ProcessTerminateEvent:
    def __init__(self, name, pid, cr3, eprocess, protection):
        self.event_type = "Process Terminate"
        self.name = name
        self.pid = pid
        self.cr3 = cr3
        self.eprocess = eprocess
        self.protection = protection


class Module:
    def __init__(self, name, start, end):
        self.name = name
        self.start = start
        self.end = end


class ModuleLoadEvent:
    def __init__(self, module, processname, pid, protection):
        self.event_type = "Module Load"
        self.module = module
        self.processname = processname
        self.pid = pid
        self.protection = protection


class ModuleUnloadEvent:
    def __init__(self, module, processname, pid, protection):
        self.event_type = "Module Unload"
        self.module = module
        self.processname = processname
        self.pid = pid
        self.protection = protection


class Instruction:
    def __init__(self, mnemonic, instruction, length):
        self.mnemonic = mnemonic
        self.instruction = instruction
        self.length = length


class ModuleAlertEvent:
    def __init__(self, attacker, victim, rip, address, processname, pid, instructions, action, func_name, protection):
        self.event_type = "Module Alert"
        self.attacker = attacker
        self.victim = victim
        self.rip = rip
        self.address = address
        self.processname = processname
        self.pid = pid
        self.instructions = instructions
        self.action = action
        self.func_name = func_name
        self.protection = protection



class Marshaller:
    def from_list_to_str(self, lst):
        st = ""
        for i in list(lst):
            if i == 0:
                break
            st += chr(i)
        return st

    def from_str_to_list(self, st, sz):
        lst = [0 for i in range(sz)]
        t = 0
        for i in st:
            lst[t] = ord(i)
            t+=1
        return lst

    def _from_evt_proc_start(self, evt, prot):
        name = self.from_list_to_str(evt.Name)
        return ProcessCreateEvent(name, evt.Pid, evt.Cr3, evt.Eprocess, prot)

    def _from_evt_proc_finish(self, evt, prot):
        name = self.from_list_to_str(evt.Name)
        return ProcessTerminateEvent(name, evt.Pid, evt.Cr3, evt.Eprocess, prot)

    def _from_evt_mod_load(self, evt, prot):
        m = Module(self.from_list_to_str(evt.Module.Name), evt.Module.Start, evt.Module.End)
        return ModuleLoadEvent(m, self.from_list_to_str(evt.ProcessName), evt.Pid, prot)

    def _from_evt_mod_unload(self, evt, prot):
        m = Module(self.from_list_to_str(evt.Module.Name), evt.Module.Start, evt.Module.End)
        return ModuleUnloadEvent(m, self.from_list_to_str(evt.ProcessName), evt.Pid , prot)

    def _from_evt_mod_alert(self, evt, prot):
        instructions = []
        attacker = Module(self.from_list_to_str(evt.Attacker.Name), evt.Attacker.Start, evt.Attacker.End)
        victim = Module(self.from_list_to_str(evt.Victim.Name), evt.Victim.Start, evt.Victim.End)
        instr_list = list(evt.Instructions)
        for i in range(evt.NumberOfInstructions):
            instructions.append(Instruction(instr_list[i].Mnemonic, self.from_list_to_str(instr_list[i].Instruction), instr_list[i].Length))

        return ModuleAlertEvent(attacker, victim, evt.Rip, evt.Address, self.from_list_to_str(evt.ProcessName), evt.Pid, instructions, evt.Action, self.from_list_to_str(evt.FunctionName), prot)

    def from_evt_to_py(self, evt):
        if evt.EventType == 0:
            return self._from_evt_proc_start(evt.union.ProcessCreateEvent, evt.Protection)
        elif evt.EventType == 1:
            return self._from_evt_proc_finish(evt.union.ProcessTerminateEvent, evt.Protection)
        elif evt.EventType == 2:
            return self._from_evt_mod_load(evt.union.ModuleLoadEvent, evt.Protection)
        elif evt.EventType == 3:
            return self._from_evt_mod_unload(evt.union.ModuleUnloadEvent, evt.Protection)
        elif evt.EventType == 4:
            return self._from_evt_mod_alert(evt.union.ModuleAlertEvent, evt.Protection)

    def from_py_to_evt(self, py):
        if py.event_type != "Module Alert":
            raise Exception("No conversion to c event other than module alert, is now %s", py.event_type)

        evt = Evt()
        evt.EventType = 4
        evt.union.ModuleAlertEvent.Attacker.Name = (c_byte * 256)(*self.from_str_to_list(py.attacker.name,256))
        evt.union.ModuleAlertEvent.Attacker.Start = py.attacker.start
        evt.union.ModuleAlertEvent.Attacker.End = py.attacker.end
        evt.union.ModuleAlertEvent.Victim.Name = (c_byte * 256)(*self.from_str_to_list(py.victim.name,256))
        evt.union.ModuleAlertEvent.Victim.Start = py.victim.start
        evt.union.ModuleAlertEvent.Victim.End = py.victim.end
        evt.union.ModuleAlertEvent.Rip = py.rip
        evt.union.ModuleAlertEvent.Address = py.address
        evt.union.ModuleAlertEvent.ProcessName = (c_byte*16)(*self.from_str_to_list(py.processname,16))
        evt.union.ModuleAlertEvent.NumberOfInstructions = len(py.instructions)

        instructions = [EvtInstruction() for i in range(10)]
        for i in range(len(py.instructions)):
            instrux = instructions[i]
            instrux.Length = py.instructions[i].length
            instrux.Mnemonic = py.instructions[i].mnemonic
            instrux.Instruction = (c_byte*128)(*self.from_str_to_list(py.instructions[i].instruction,128))
            instructions[i] = instrux

        evt.union.ModuleAlertEvent.Instructions = (EvtInstruction*10)(*instructions)

        return evt



import time
import json
import threading

class EvtEncoder(json.JSONEncoder):
    def default(self, o):
        return o.__dict__

class DllHandler:

    def __init__(self):
        self.dll = CDLL('./HyperComm.dll')
        self.observers = []


    def subscribe(self, function_to_call):
        self.observers.append(function_to_call)

    def start_listening(self):
        t = threading.Thread(target=self.listen_for_events)
        t.start()

    def listen_for_events(self):
        m = Marshaller()
        while True:
            q = c_void_p()
            status = self.dll.HyperCommGetLatestEvent(byref(q))
            if status != 0:
                time.sleep(1)
                continue
            ans = cast(q, POINTER(Evt)).contents
            #json.dumps(m.from_evt_to_py(ans), cls=EvtEncoder)

            for observer in self.observers:
                observer(m.from_evt_to_py(ans), self)

    def add_protection_process(self, process_name, mask):
        self.dll.HyperCommAddProtectionToProcess(process_name, mask)

    def add_alert_exception(self, evt):
        #print(evt)
        self.dll.HyperCommExceptAlert(byref(evt))

if __name__ == "__main__":
    def printer(evt, obj):
        print(json.dumps(evt, cls=EvtEncoder))

        if(evt.event_type == "Module Alert"):
            m = Marshaller()
            x = m.from_py_to_evt(evt)
            obj.add_alert_exception(x)

    dh = DllHandler()

    dh.subscribe(printer)

    dh.start_listening()

