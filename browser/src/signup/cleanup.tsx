import React, { Component } from 'react';
import { connect } from 'react-redux';
import { RootState, AppDispatch } from '../store';
import { SignupState, deleteSignup } from '../store/signup';

type SignupDisposeProps = {
  dispatch: AppDispatch;
  state: SignupState,
};

// Cleanup the signup state when the component is unmounted.
class SignupDispose extends Component<SignupDisposeProps> {
  componentWillUnmount() {
    const { state, dispatch } = this.props;
    const dispose = async () => {
      // Dispose of Webassembly and Javascript state
      await dispatch(deleteSignup(state.signup));
    }
    dispose();
  }

  render() {
    // NOTE: returning null here annoys the typescript typechecker
    return <></>;
  }
}

const ConnectedDispose = connect((root: RootState) => {
  return { state: root.signup }
}, (dispatch: AppDispatch) => { return { dispatch } } )(SignupDispose);

export default ConnectedDispose;
