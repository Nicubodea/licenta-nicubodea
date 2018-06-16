import React, { Component } from 'react';
import {Header} from "./Header";
import {GenericService} from "../service/GenericService";

class ExceptionRow extends Component {
    constructor(props) {
        super(props);

        this.service = new GenericService();
    }

    onClickRemove() {
        this.service.remove_exception(this.props.event.id, this.props.event.alert.id).then(x => {
            this.props.row_parent.onClickRefresh.bind(this.props.row_parent)();
        })
    }

    render() {
        return (
            <tr className={"table-info"}>
                <td>{this.props.event.alert.process_name}</td>
                <td>{this.props.event.alert.attacker_name}</td>
                <td>{this.props.event.alert.victim_name}</td>
                <td><button class="btn btn-dark" onClick={this.onClickRemove.bind(this)}>Remove</button><br/></td>
            </tr>
        )
    }


}

export class ExceptionsPage extends Component {
    constructor(props) {
        super(props);
        this.state = {
            exceptions: []
        };

        this.service = new GenericService();


        this.service.get_exceptions().then((result) => {
            this.setState({exceptions:result});
        });

    }

    onClickRefresh() {
        this.service.get_exceptions().then((result) => {
            this.setState({exceptions:result});
        });
    }

    render() {
        return (
            <div class = "container-fluid">
                <Header/>
                <div class = "container">
                    <button class="btn btn-dark" onClick={this.onClickRefresh.bind(this)}>Refresh</button><br/>
                    The current exceptions are:

                <table className={"table"}>
                    <tr>
                        <th>
                            Process
                        </th>
                        <th>
                            Attacker
                        </th>
                        <th>
                            Victim
                        </th>
                        <th>
                            Except
                        </th>
                    </tr>
                    {
                        this.state.exceptions.map(x => <ExceptionRow event={x} row_parent={this}/>)
                    }
                </table>
                </div>

            </div>
        );
    }
}