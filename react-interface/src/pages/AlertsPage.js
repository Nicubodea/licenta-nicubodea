import React, { Component } from 'react';
import {Header} from "./Header";
import {GenericService} from "../service/GenericService";
import {Link} from "react-router-dom";

class AlertRow extends Component {
    constructor(props) {
        super(props);
        this.service = new GenericService();
    }

    add_new_exception() {
        if(this.props.event.excepted) {
            alert("Already excepted!");
            return;
        }

        this.service.except_alert(this.props.event.alert.id).then(x => {
            this.props.row_parent.onClickRefresh.bind(this.props.row_parent)();
        });
    }


    render() {
        let event_class = "table-danger";

        if(this.props.event.excepted)
        {
            event_class = "table-success";
        }

        return (
            <tbody>
            <tr className={event_class}>
                <td>
                    {this.props.event.alert.attacker_name}
                </td>
                <td>
                    {this.props.event.alert.victim_name}
                </td>
                <td>
                    {this.props.event.alert.process_name}
                </td>
                <td>
                    {this.props.event.alert.pid}
                </td>
                <td>
                    {this.props.event.session}
                </td>
                <td>
                    <button className={"btn btn-dark"} onClick={this.add_new_exception.bind(this)}>Except</button>
                </td>
                <td>
                    <Link className={"btn btn-dark"} to={{pathname:"/events", state: {id: this.props.event.timeline_id}}}>Go to timeline</Link>
                </td>
            </tr>
            </tbody>
        )
    }
}


export class AlertsPage extends Component {
    constructor(props) {
        super(props);
        this.state = {
            alerts: []
        };

        this.service = new GenericService();

        this.service.get_alerts().then(result => {
            this.setState({alerts:result});
        })
    }

    onClickRefresh() {
        this.service.get_alerts().then((timeline_list) => {
            this.setState({alerts: timeline_list});
        });
    }

    render() {
        return (
            <div class = "container-fluid">
                <Header/>
                <div class = "container">
                    <button class="btn btn-dark" onClick={this.onClickRefresh.bind(this)}>Refresh</button><br/>
                    The alerts that were triggered on the system are:
                <table class="table">
                    <tr>
                        <th>
                            Attacker
                        </th>
                        <th>
                            Victim
                        </th>
                        <th>
                            Process
                        </th>
                        <th>
                            PID
                        </th>
                        <th>
                            Session
                        </th>
                        <th>
                            Except
                        </th>
                        <th>
                            Go to timeline
                        </th>
                    </tr>
                    {
                        this.state.alerts.map(x => <AlertRow event={x} row_parent={this}/>)
                    }
                </table>
                </div>
            </div>
        );
    }
}