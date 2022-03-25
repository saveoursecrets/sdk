import React from 'react';
import {useDispatch, useSelector} from 'react-redux';

import Tooltip from "@mui/material/Tooltip";
import IconButton from "@mui/material/IconButton";
import LoginIcon from "@mui/icons-material/Login";
import LogoutIcon from "@mui/icons-material/Logout";

import {userSelector, setAuthToken} from './store/user';
import {vaultsSelector, lockAll} from './store/vaults';

export default function AppBarActions() {
  const {vaults} = useSelector(vaultsSelector);
  const {token} = useSelector(userSelector);
  const dispatch = useDispatch();

  const logout = () => {
    dispatch(lockAll(vaults));
    dispatch(setAuthToken(null))
  }

  const Login = () => (
    <Tooltip title="Login">
      <IconButton
        color="inherit"
        aria-label="logout"
        onClick={() => console.log("login")}
      >
        <LoginIcon />
      </IconButton>
    </Tooltip>
  );

  const Logout = () => (
    <Tooltip title="Logout">
      <IconButton
        color="inherit"
        aria-label="logout"
        onClick={logout}>
        <LogoutIcon />
      </IconButton>
    </Tooltip>
  );

  return <>
    {token === null ? <Login /> : <Logout />}
  </>;
}
