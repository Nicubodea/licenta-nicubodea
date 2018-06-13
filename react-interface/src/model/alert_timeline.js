export class AlertTimeline {
    constructor(id, alert, excepted, session, timeline_id) {
        this.id = id;
        this.alert = alert;
        this.excepted = excepted;
        this.session = session;
        this.timeline_id = timeline_id;
    }
}