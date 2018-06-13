import {GenericService} from "../service/GenericService";
import React, { Component } from 'react';
import {Header} from "./Header";
import {Link} from "react-router-dom";

class TimelineRow extends Component {
    constructor(props) {
        super(props);
    }

    render() {
        let current_state = "";
        let decided_class = "active";
        if(this.props.state == 0)
        {
            current_state = "not protected";
            decided_class = "table-primary";
        }
        if(this.props.state == 1)
        {
            current_state = "protected";
            decided_class = "table-success";
        }
        if(this.props.state == 2)
        {
            current_state = "process was attacked and attack was blocked";
            decided_class = "table-warning";
        }
        if(this.props.state == 3)
        {
            current_state = "process was attacked and attack was NOT blocked";
            decided_class = "table-danger";
        }

        let completed_text = "";
        if (this.props.completed) {
            completed_text = "current timeline is completed at: " + this.props.date_ended;
            if(decided_class === "table-primary" || decided_class === "table-success") {
                decided_class = "table-active";
            }
        }
        else
        {
            completed_text = "current timeline is still running";
        }


        return (
            <tr className={decided_class}>
                    <td>
                        {this.props.date_started}
                    </td>
                    <td>
                        {this.props.process}
                    </td>
                    <td>
                        {this.props.pid}
                    </td>
                    <td>
                        {this.props.session}
                    </td>

                    <td>
                        {current_state}
                    </td>
                    <td>
                        {completed_text}
                    </td>
                    <td>
                        <Link className={"btn btn-dark"} to={{pathname:"/events", state: {id: this.props.id}}}>Show events</Link>
                    </td>
            </tr>
        )
    }
}

export class TimelinesPage extends Component {
    constructor(props) {
        super(props);

        this.state = {
            timelines: []
        };

        this.service = new GenericService();

        this.service.get_all_timelines().then((timeline_list) => {
            this.setState({timelines: timeline_list});
        });

    }

    onClickRefresh() {
        this.service.get_all_timelines().then((timeline_list) => {
            this.setState({timelines: timeline_list});
        });
    }

    render() {
        return (
            <div class="container-fluid">
            <Header/>

                <div className="container">
                    <p>Here are the time lines during all the sessions run on this protected PC</p>
                    <button class="btn btn-dark" onClick={this.onClickRefresh.bind(this)}>Refresh</button>
                    <table className = "table">
                    <tr>
                        <th>
                         Date started
                        </th>
                        <th>
                            Process name
                        </th>
                        <th>
                            Process ID
                        </th>
                        <th>
                            Session
                        </th>
                        <th>
                            Current state
                        </th>
                        <th>
                            Completed
                        </th>
                        <th>
                            Events
                        </th>
                    </tr>

                    {
                        this.state.timelines.map(timeline =>
                            <TimelineRow id={timeline.id}
                                process={timeline.process}
                                pid={timeline.pid}
                                completed={timeline.completed}
                                date_started={timeline.date_started}
                                date_ended={timeline.date_ended}
                                session={timeline.session}
                                events={timeline.events}
                                state={timeline.state}
                            />
                        )
                    }
                    </table>
                </div>

            </div>
        )
    }
}