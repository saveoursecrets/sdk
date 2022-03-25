import React from "react";
import { useDispatch, useSelector } from "react-redux";

import ButtonGroup from "@mui/material/ButtonGroup";
import Button from "@mui/material/Button";
import LoginIcon from "@mui/icons-material/Login";

import { setAuthToken } from "./store/user";

export default function AppBarActions() {
  const dispatch = useDispatch();

  const login = () => {
    dispatch(setAuthToken("mock-auth-token"));
  };

  return (
    <>
      <ButtonGroup variant="contained" aria-label="signup or login">
        <Button>Signup</Button>
        <Button onClick={login} endIcon={<LoginIcon />}>
          Login
        </Button>
      </ButtonGroup>
    </>
  );
}
