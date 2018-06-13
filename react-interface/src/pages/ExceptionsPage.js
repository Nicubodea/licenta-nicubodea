import React, { Component } from 'react';
import {Header} from "./Header";

export class ExceptionsPage extends Component {
    constructor(props) {
        super(props);
    }

    render() {
        return (
            <div>
                <Header/>
                <p>Hello world!</p>
            </div>
        );
    }
}