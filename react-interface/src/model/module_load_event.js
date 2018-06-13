export class ModuleLoadEvent {
    constructor(id, name, start, end, process_name, pid, protect, date_event, type) {
        this.id = id;
        this.name = name;
        this.start = start;
        this.end = end;
        this.process_name = process_name;
        this.pid = pid;
        this.protect = protect;
        this.date_event = date_event;
        this.type = type;
    }
}