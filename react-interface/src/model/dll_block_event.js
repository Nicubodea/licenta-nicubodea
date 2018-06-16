export class DllBlockEvent {
    constructor(id, dll_name, process_name, pid, action, protection, event_date, type) {
        this.id = id;
        this.dll_name = dll_name;
        this.process_name = process_name;
        this.pid = pid;
        this.action = action;
        this.protection = protection;
        this.event_date = event_date;
        this.type = type;
    }
}