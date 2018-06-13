import React, { Component } from 'react';
import {Header} from "./Header";

export class HomePage extends Component {
    constructor(props) {
        super(props);
    }

    render() {
        return (
            <div class="container-fluid">
                <Header/>
                <div class="container">
                    Hello world!
                </div>
            </div>
        );
    }
}