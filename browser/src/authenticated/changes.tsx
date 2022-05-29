import React, { Component } from "react";
import { connect } from "react-redux";
import api from '../store/api';
import { RootState, AppDispatch } from "../store";
import { AccountState } from "../store/account";

type ChangesProps = {
  dispatch: AppDispatch;
  state: AccountState;
};

type ChangesState = {
  eventSource?: EventSource;
};

// Cleanup the signup state when the component is unmounted.
class Changes extends Component<ChangesProps, ChangesState> {

  constructor(props: ChangesProps) {
    super(props);
    this.state = { eventSource: null };
  }

  componentDidMount() {
    const getChangesEventSource = async() => {
      const { account } = this.props.state;
      const eventSource = await api.getChanges(account);

      /*
      eventSource.addEventListener("error", (e) => {
        console.error("SSE Error", e);
      });

      eventSource.addEventListener("open", (e) => {
        console.log("SSE stream was opened!!!");
      });
      */

      eventSource.addEventListener("create", (e) => {
        console.log("SSE create event", e.data);
      });

      eventSource.addEventListener("update", (e) => {
        console.log("SSE update event", e.data);
      });

      eventSource.addEventListener("delete", (e) => {
        console.log("SSE delete event", e.data);
      });

      this.setState( { eventSource } );
    }
    getChangesEventSource();
  }

  componentWillUnmount() {
    const { eventSource } = this.state;
    if (eventSource) {
      eventSource.close();
    }
  }

  render() {
    // NOTE: returning null here annoys the typescript typechecker
    return <></>;
  }
}

const ConnectedChanges = connect(
  (root: RootState) => {
    return { state: root.account };
  },
  (dispatch: AppDispatch) => {
    return { dispatch };
  }
)(Changes);

export default ConnectedChanges;
