import React, { Component } from 'react';
import {Header} from "./Header";
import {GenericService} from "../service/GenericService";

class ProtectedRow extends Component {
    constructor(props) {
        super(props);
        this.state = {
                ntdll: !!(this.props.process.mask & 1),
                kernel32: !!(this.props.process.mask & 2),
                kernelbase: !!(this.props.process.mask & 4),
                allow: !!(this.props.process.mask & 16),
                dll: !!(this.props.process.mask & 32)
        };

        this.service = new GenericService();
    }

    get_mask_from_state() {
        let mask = 0;
        if(this.state.ntdll) {
            mask = mask | 1;
        }
        if(this.state.kernel32) {
            mask = mask | 2;
        }
        if(this.state.kernelbase) {
            mask = mask | 4;
        }
        if(this.state.allow) {
            mask = mask | 16;
        }
        if(this.state.dll) {
            mask = mask | 32;
        }
        return mask;

    }

    protectionHasChanged(event) {
        let target = event.target;
        let name = target.name;
        let value = target.checked;
        this.setState({
            [name]: value
        });
    }

    changeProtection() {
        this.service.modify_protection(this.props.process.processname, this.get_mask_from_state()).then(result => {
            this.props.parent_row.onClickRefresh.bind(this.props.parent_row)();
            alert("Successfully changed!");
        });
    }

    removeProtection() {
        this.service.remove_protection(this.props.process.processname).then(x => {
            this.props.parent_row.onClickRefresh.bind(this.props.parent_row)();
            alert("Successfully removed!");
        })
    }

    render() {

        return (
            <tbody>
                <tr className={"table-primary"}>
                    <td>
                        {this.props.process.processname}
                    </td>
                    <td>
                        <input type={"checkbox"} name={"ntdll"} checked={this.state.ntdll} onChange={this.protectionHasChanged.bind(this)}/>
                    </td>
                    <td>
                        <input type={"checkbox"} name={"kernel32"} checked={this.state.kernel32} onChange={this.protectionHasChanged.bind(this)}/>
                    </td>
                    <td>
                        <input type={"checkbox"} name={"kernelbase"} checked={this.state.kernelbase} onChange={this.protectionHasChanged.bind(this)}/>
                    </td>
                    <td>
                        <input type={"checkbox"} name={"allow"} checked={this.state.allow} onChange={this.protectionHasChanged.bind(this)}/>
                    </td>
                    <td>
                        <input type={"checkbox"} name={"dll"} checked={this.state.dll} onChange={this.protectionHasChanged.bind(this)}/>
                    </td>
                    <td>
                        <button class={"btn btn-dark"} onClick={this.changeProtection.bind(this)}>Change</button>
                    </td>
                    <td>
                        <button class={"btn btn-dark"} onClick={this.removeProtection.bind(this)}>Remove</button>
                    </td>
                </tr>
            </tbody>

        )
    }

}

export class ProtectionPage extends Component {
    constructor(props) {
        super(props);
        this.state = {
            prots:[],
            ntdll: false,
            kernel32: false,
            kernelbase: false,
            allow: false,
            dll: false,
            inputValue: ""
        };

        this.service = new GenericService();

        this.service.get_protected_processes().then(result => {
            this.setState({prots: result});
        });
    }

    get_mask_from_state() {
        let mask = 0;
        if(this.state.ntdll) {
            mask = mask | 1;
        }
        if(this.state.kernel32) {
            mask = mask | 2;
        }
        if(this.state.kernelbase) {
            mask = mask | 4;
        }
        if(this.state.allow) {
            mask = mask | 16;
        }
        if(this.state.dll) {
            mask = mask | 32;
        }
        return mask;

    }

    onClickRefresh() {
        this.service.get_protected_processes().then((result) => {
            this.setState({prots: result});
        });
    }

    protectionHasChanged(event) {
        let target = event.target;
        let name = target.name;
        let value = target.checked;
        this.setState({
            [name]: value
        });
    }

    newProtected(event) {
        this.service.add_protected_process(this.state.inputValue, this.get_mask_from_state()).then(x => {
            this.onClickRefresh();
            alert("Successfully added!");
        })
    }

    inputHasChanged(event) {
        this.setState({inputValue:event.target.value});
    }

    render() {
        return (
            <div class="container-fluid">
                <Header/>
                <div class="container">
                    Here you can add and remove processes from protection<br/>

                <div class = "form-group">
                    <label for="process">Process name:</label>
                    <input type={"text"} class="form-control" id={"process"} value={this.state.inputValue} onChange={this.inputHasChanged.bind(this)}/>

                </div>

                    <div class ="container">
                    <div class = "form-group">
                        <div class="checkbox">
                <label class="">
                    <input type="checkbox" name={"ntdll"} defaultChecked={this.state.ntdll} onChange={this.protectionHasChanged.bind(this)}/>Protect ntdll.dll
                </label>
                        </div>
                        <div class="checkbox">
                <label class="">
                    <input type={"checkbox"} name={"kernel32"} defaultChecked={this.state.kernel32} onChange={this.protectionHasChanged.bind(this)}/>Protect kernel32.dll
                </label>
                        </div>
                        <div class="checkbox">
                <label class="">
                    <input type={"checkbox"} name={"kernelbase"} defaultChecked={this.state.kernelbase} onChange={this.protectionHasChanged.bind(this)}/>Protect kernelbase.dll
                </label>
                        </div>
                        <div class="checkbox">
                <label class="">
                    <input type={"checkbox"} name={"allow"} defaultChecked={this.state.allow} onChange={this.protectionHasChanged.bind(this)}/>Only notify suspicious activity
                </label>
                        </div>
                        <div class="checkbox">
                <label class="">
                    <input type={"checkbox"} name={"dll"} defaultChecked={this.state.dll} onChange={this.protectionHasChanged.bind(this)}/>Apply blocking DLL rules

                </label>
                        </div>
                    </div>
                        <button class="btn btn-dark" onClick={this.newProtected.bind(this)}>Add process</button>
                    </div>
                    <table class="table">
                        <tr>
                            <th>Process name</th>
                            <th>Protect ntdll.dll</th>
                            <th>Protect kernel32.dll</th>
                            <th>Protect kernelbase.dll</th>
                            <th>Only notify suspicious activity</th>
                            <th>Apply blocking DLL rules</th>
                            <th>Change</th>
                            <th>Remove</th>
                        </tr>
                        {
                        this.state.prots.map(x => <ProtectedRow process = {x} parent_row = {this}/>)
                        }
                    </table>

                </div>
            </div>
        );
    }
}