import React, { Component } from 'react';
import logo from './logo.svg';
import './App.css';
import '../node_modules/bootstrap/dist/css/bootstrap.css'
import { BrowserRouter as Router, Switch, Route, Link } from 'react-router-dom';

import {HomePage} from "./pages/HomePage";
import {TimelinesPage} from "./pages/TimelinesPage";
import {AlertsPage} from "./pages/AlertsPage";
import {ExceptionsPage} from "./pages/ExceptionsPage";
import {ProtectionPage} from "./pages/ProtectionPage";
import {DllPage} from "./pages/DllPage";
import {ShowEventsPage} from "./pages/ShowEventsPage";


class App extends Component {
  render() {
    return (
        <Router>
            <div>
                <Switch>
                    <Route exact path='/' component={HomePage} />
                    <Route exact path='/timelines' component={TimelinesPage} />
                    <Route exact path='/alerts' component={AlertsPage} />
                    <Route exact path='/exceptions' component={ExceptionsPage} />
                    <Route exact path='/protection' component={ProtectionPage} />
                    <Route exact path='/dlls' component={DllPage} />
                    <Route exact path='/events' component={ShowEventsPage} />
                </Switch>
            </div>
        </Router>
    );
  }
}

export default App;
