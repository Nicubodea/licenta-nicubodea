import {Timeline} from "../model/timeline";
import React, { Component } from 'react';
import {CreateProcessEvent} from "../model/create_process_event";
import {TerminateProcessEvent} from "../model/terminate_process_event";
import {ModuleLoadEvent} from "../model/module_load_event";
import {ModuleUnloadEvent} from "../model/module_unload_event";
import {Instruction} from "../model/instruction";
import {ModuleAlertEvent} from "../model/module_alert_event";
import {AlertTimeline} from "../model/alert_timeline";
import {ProtectedProcess} from "../model/protected_process";

export class GenericService extends Component {

    constructor() {
        super();

        this.server = "http://192.168.30.128:80"
    }

    get_create_proc_event(result) {
        /*
                this.id = id;
        this.name = name;
        this.pid = pid;
        this.cr3 = cr3;
        this.eprocess = eprocess;
        this.protection = protection;
        this.event_date = event_date;

         */
        return new CreateProcessEvent(result['id'], result['name'], result['pid'], result['cr3'],
            result['eprocess'], result['protection'], result['event_date'], result['type']);
    }

    get_delete_proc_event(result) {

        return new TerminateProcessEvent(result['id'], result['name'], result['pid'], result['cr3'],
            result['eprocess'], result['protection'], result['event_date'], result['type']);

    }
    get_module_load_event(result) {
        return new ModuleLoadEvent(result['id'], result['name'], result['start'], result['end'],
            result['process_name'], result['pid'], result['protected'], result['event_date'], result['type']);
    }
    get_module_unload_event(result) {

        return new ModuleUnloadEvent(result['id'], result['name'], result['start'], result['end'],
            result['process_name'], result['pid'], result['protected'], result['event_date'], result['type']);
    }
    get_alert_event(result) {
        let instructions = [];
        for(let i = 0; i<result['instructions'].length; i++)
        {
            instructions.push(new Instruction(result['instructions'][i]['mnemonic'], result['instructions'][i]['text'],
                result['instructions'][i]['length']));
        }

        return new ModuleAlertEvent(result['id'], result['attacker_name'], result['attacker_start'], result['attacker_end'],
            result['victim_name'], result['victim_start'], result['victim_end'], result['process_name'], result['pid'],
            result['rip'], result['address'], result['functionname'], result['action'], result['protection'],
            instructions, result['event_date'], result['type']);
    }

    get_one_event(result) {
        if(result["type"] == 0)
        {
            return this.get_create_proc_event(result);
        }
        else if(result["type"] == 1)
        {
            return this.get_delete_proc_event(result);
        }
        else if(result["type"] == 2)
        {
            return this.get_module_load_event(result);
        }
        else if(result["type"] == 3)
        {
            return this.get_module_unload_event(result);
        }
        else if(result["type"] == 4)
        {
            return this.get_alert_event(result);
        }
    }

    get_timeline_events(result) {
        let events = [];
        for(let i = 0; i<result['events'].length; i++)
        {
            events.push(this.get_one_event(result['events'][i]));
        }

        let toret = new Timeline(result['id'],
            result['process'],
            result['pid'],
            result['completed'],
            result['date_started'],
            result['date_ended'],
            result['session'],
            events,
            result['state']);
        console.log(toret);
        return toret;
    }

    get_one_timeline(result) {
        return new Timeline(result['id'],
            result['process'],
            result['pid'],
            result['completed'],
            result['date_started'],
            result['date_ended'],
            result['session'],
            result['events'],
            result['state']);
    }

    get_timelines_from_list(result) {
        let answer = [];

        for(let i = 0; i< result.length; i++) {
            answer.push(this.get_one_timeline(result[i]))
        }

        return answer;
    }

    get_all_timelines() {
        return fetch(this.server + "/get_timelines", {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            }
        }).then(result => {
            return result.json();
        }).then(result => {
            return this.get_timelines_from_list(result["answer"])
        });
    }

    get_timeline_by_id(id) {
        return fetch(this.server + "/get_timeline?id=" + id, {
                method: 'GET',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/x-www-form-urlencoded',
                }
            }).then(result => {
                return result.json();
        }).then(result => {
            return this.get_timeline_events(result["answer"]);
        })
    }

    get_alert_timeline(result) {
        return new AlertTimeline(
            result['id'],
            this.get_alert_event(result['alert']),
            result['excepted'],
            result['session'],
            result['timeline_id']
        )
    }

    get_alert_timelines(result) {
        let timelines = [];
        for(let i = 0; i<result.length; i++)
        {
            timelines.push(this.get_alert_timeline(result[i]));
        }
        return timelines;
    }

    get_alerts() {
        return fetch(this.server + "/get_alerts", {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            }
        }).then(result => {
            return result.json();
        }).then(result => {
            return this.get_alert_timelines(result["answer"]);
        })
    }

    except_alert(alert_id) {
        return fetch(this.server + "/add_exception", {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: "alert_id="+alert_id
        }).then(result => {
            return result.json();
        }).then(result => {
            return result;
        })
    }

    get_procs(result) {
        let ans = [];
        for(let i = 0; i<result.length; i++)
        {
            ans.push(new ProtectedProcess(result[i]['processname'], result[i]['mask']));
        }
        return ans;
    }

    get_protected_processes() {
        return fetch(this.server + "/get_protected", {
            method: 'GET',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            }
        }).then(result => {
            return result.json();
        }).then(result => {
            return this.get_procs(result["answer"]);
        })
    }

    add_protected_process(name, mask) {
        return fetch(this.server + "/add_prot_proc", {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: "process="+name+"&mask="+mask
        }).then(result => {
            return result.json();
        }).then(result => {
            return result;
        })
    }

    modify_protection(name, mask) {
        return fetch(this.server + "/change_prot_proc", {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: "process="+name+"&mask="+mask
        }).then(result => {
            return result.json();
        }).then(result => {
            return result;
        })
    }

    remove_protection(name, mask) {
        return fetch(this.server + "/remove_prot_proc", {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            body: "process="+name
        }).then(result => {
            return result.json();
        }).then(result => {
            return result;
        })
    }

}