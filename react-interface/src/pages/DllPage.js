import React, { Component } from 'react';
import {Header} from "./Header";
import {GenericService} from "../service/GenericService";

class DLLRow extends Component {
    constructor(props) {
        super(props);
        this.service = new GenericService();
    }

    onClickRemove() {
        this.service.remove_blocked_dll(this.props.event.dll_name).then((x) => {
            this.props.row_parent.onClickRefresh.bind(this.props.row_parent)();
        })
    }

    render() {
        return (
            <tr class="table-info">
                <td>
                    {this.props.event.dll_name}
                </td>
                <td>
                    <button class="btn btn-dark" onClick={this.onClickRemove.bind(this)}>Remove</button><br/>
                </td>
            </tr>
        )
    }
}

export class DllPage extends Component {
    constructor(props) {
        super(props);
        this.state = {
            dlls: [],
            inputValue: ""
        };

        this.service = new GenericService();
        this.service.get_all_blocked_dlls().then((timeline_list) => {
            this.setState({dlls: timeline_list});
        });

    }

    onClickRefresh() {
        this.service.get_all_blocked_dlls().then((timeline_list) => {
            this.setState({dlls: timeline_list});
        });
    }

    inputHasChanged(event) {
        this.setState({inputValue:event.target.value});
    }

    onClickAddDll() {
        this.service.add_blocked_dll(this.state.inputValue).then((x) => {
            this.onClickRefresh();
        });
    }

    render() {
        return (
            <div class = "container-fluid">
                <Header/>
                <div class = "container">

                    <div class = "form-group">
                        <label for="dll_name">Process name:</label>
                        <input type={"text"} class="form-control" id={"dll_name"} value={this.state.inputValue} onChange={this.inputHasChanged.bind(this)}/>

                    </div>

                    <div>
                        <button class="btn btn-dark" onClick={this.onClickAddDll.bind(this)}>Block DLL</button><br/>
                    </div>

                    The current blocked dlls are:
                    <div>
                    <button class="btn btn-dark" onClick={this.onClickRefresh.bind(this)}>Refresh</button><br/>
                    </div>

                    <table className={"table"}>
                        <tr>
                            <th>
                                DLL Name
                            </th>
                            <th>
                                Remove
                            </th>
                        </tr>
                        {
                            this.state.dlls.map(x => <DLLRow event={x} row_parent={this}/>)
                        }
                    </table>
                </div>

            </div>
        );
    }
}