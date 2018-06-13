import React, { Component } from 'react';
import {Link} from "react-router-dom";

export class Header extends Component {
    constructor(props) {
        super(props);

    }

    render() {
        return (
            <div class="container">
                <nav class ="navbar navbar-expand-sm bg-dark navbar-dark">
                        <div class = "navbar-header">
                            <a class ="navbar-brand" href={"#"}> Hypervisor Management Interface </a>
                        </div>
                        <ul class="navbar-nav">
                            <li class="nav-item">
                                <Link class={"nav-link"} to={"/"}>Home</Link>
                            </li>
                            <li class="nav-item">
                                <Link class={"nav-link"} to={"/timelines"}>Timeline Management</Link>
                            </li>
                            <li class="nav-item">
                                <Link class={"nav-link"} to={"/alerts"}>Alert Management</Link>
                            </li>
                            <li class="nav-item">
                                <Link class={"nav-link"} to={"/exceptions"}>Exclusion Management</Link>
                            </li>
                            <li class="nav-item">
                                <Link class={"nav-link"} to={"/protection"}>Protection Policy</Link>
                            </li>
                            <li class="nav-item">
                                <Link class={"nav-link"} to={"/dlls"}>DLL Blocking Management</Link>
                            </li>
                        </ul>
                </nav>
            </div>
        )
    }
}