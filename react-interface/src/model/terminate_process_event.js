export class TerminateProcessEvent {
    constructor(id, name, pid, cr3, eprocess, protection, event_date, type) {
        this.id = id;
        this.name = name;
        this.pid = pid;
        this.cr3 = cr3;
        this.eprocess = eprocess;
        this.protection = protection;
        this.event_date = event_date;
        this.type = type;
    }
}