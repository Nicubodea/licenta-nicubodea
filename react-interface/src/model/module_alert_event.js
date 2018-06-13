export class ModuleAlertEvent {
    constructor(id, attacker_name, attacker_start, attacker_end, victim_name, victim_start, victim_end,
                process_name, pid, rip, address, functionname, action, protection, instructions, event_date, type) {
        this.id = id;
        this.attacker_name = attacker_name;
        this.attacker_start = attacker_start;
        this.attacker_end = attacker_end;
        this.victim_name = victim_name;
        this.victim_start = victim_start;
        this.victim_end = victim_end;
        this.process_name = process_name;
        this.pid = pid;
        this.rip = rip;
        this.address = address;
        this.functionname = functionname;
        this.action = action;
        this.protection = protection;
        this.instructions = instructions;
        this.event_date = event_date;
        this.type = type;
    }
}