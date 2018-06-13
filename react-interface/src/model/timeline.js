export class Timeline {
    constructor(id, process, pid, completed, date_started, date_ended, session, events, state) {
        this.id = id;
        this.process = process;
        this.pid = pid;
        this.completed = completed;
        this.date_started = date_started;
        this.date_ended = date_ended;
        this.session = session;
        this.events = events;
        this.state = state;
    }
}