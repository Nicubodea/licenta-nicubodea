import {GenericService} from "../service/GenericService";
import React, { Component } from 'react';
import {Header} from "./Header";
import {Link} from "react-router-dom";
import {Timeline} from "../model/timeline";


class EventDetails extends Component {
    constructor(props) {
        super(props);
    }
    render() {
        if(this.props.show) {
            return (

                <tr>
                    <td colspan="3">
                    {
                        this.props.event.name
                    }
                    </td>
                </tr>
            )
        }
        return null;
    }

}

class EventRow extends Component {
    constructor(props) {
        super(props);
        this.state = {
            pointing_arrow: "arrow down",
            show_details: 1
        }
    }



    moreDetailsClicked() {
        if(this.state.show_details) {
            this.setState({show_details:0, pointing_arrow:"arrow up"});
            // blah blah blah, show details
        }
        else
        {
            this.setState({show_details:1, pointing_arrow:"arrow down"});
            // blah blah blah, hide details
        }
    }
    render() {
        let event_type = "";
        let event_description = "";
        let event_class = "table-info";

        if(this.props.event.type == 0)
        {
            event_type = "Process Create";
            event_description = "The process with pid " + this.props.event.pid + " and name " + this.props.event.name + " has been created"
        }
        if(this.props.event.type == 1)
        {
            event_type = "Process Terminate";
            event_description = "The process with pid " + this.props.event.pid + " and name " + this.props.event.name + " has terminated"
        }
        if(this.props.event.type == 2)
        {
            event_type = "Library Load";
            event_description = "Library " + this.props.event.name +  " has loaded. The library is ";
            if(this.props.event.protect == 1)
            {
                event_description += "protected";
                event_class = "table-success";
            }
            else
            {
                event_description += "not protected";
            }
        }
        if(this.props.event.type == 3)
        {
            event_type = "Module Unload";
            event_description = "Library " + this.props.event.name +  " has unloaded"
        }
        if(this.props.event.type == 4)
        {
            event_type = "Alert";
            event_description = "Library " + this.props.event.attacker_name + " has tried to write inside " + this.props.event.victim_name;
            if(this.props.event.action == 1)
            {
                event_description += ". The action was blocked";
                event_class = "table-warning";
            }
            else
            {
                event_description += ". The action was NOT blocked";
                event_class = "table-danger";
            }
        }

        return (
            <tbody>
            <tr className={event_class}>
                <td>
                    {event_type}
                </td>
                <td>
                    {event_description}
                </td>
                <td>
                    <i class={this.state.pointing_arrow} onClick={this.moreDetailsClicked.bind(this)}>
                    </i>
                </td>

            </tr>
            <EventDetails show={!this.state.show_details} event={this.props.event} timeline={this.props.timeline}/>
            </tbody>
        )
    }
}

export class ShowEventsPage extends Component {
    constructor(props) {
        super(props);

        this.state = {
            timeline_id: this.props.location.state.id,
            timeline: new Timeline("", "", "", "", "", "", "", [{protection: ""}], "")
        };

        this.service = new GenericService();

        this.service.get_timeline_by_id(this.state.timeline_id).then(result => {
            this.setState({timeline: result});
        })

    }

    onClickRefresh() {
        this.service.get_timeline_by_id(this.state.timeline_id).then(result => {
            this.setState({timeline: result});
        });
    }

    render() {
        let completion_text = "";
        if(this.state.timeline && this.state.timeline.completed)
        {
            completion_text = "completed, completion date " + this.state.timeline.date_ended;
        }
        else
        {
            completion_text = "still running"
        }
        return (
            <div class="container-fluid">
            <Header/>
                <div class="container">
                    <button class="btn btn-dark" onClick={this.onClickRefresh.bind(this)}>Refresh</button><br/>
                    Showing events for timeline {this.state.timeline.process} (with PID {this.state.timeline.pid}). <br/>
                    Timeline started on {this.state.timeline.date_started}, the process having protection {this.state.timeline.events[0].protection} <br/>
                    Timeline is now {completion_text} <br/>
                    Events during this timeline:
                    <table className={"table"}>

                        <tr>
                            <th>
                                Event
                            </th>
                            <th>
                                Event description
                            </th>
                            <th>
                                Details
                            </th>
                        </tr>
                        {this.state.timeline.events.map(x=> <EventRow event={x}
                                                                timeline={this.state.timeline}
                        />)
                        }
                    </table>

                </div>
            </div>
        )
    }
}
