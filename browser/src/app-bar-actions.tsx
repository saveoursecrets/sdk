import React from "react";
import { useDispatch } from "react-redux";

import ButtonGroup from "@mui/material/ButtonGroup";
import Button from "@mui/material/Button";
import LoginIcon from "@mui/icons-material/Login";

import { login } from "./store/user";

export default function AppBarActions() {
  const dispatch = useDispatch();

  const onLogin = () => {
    const mock = {
      token: "mock-logged-in-token",
      address: "0x8a67d6f4aae8165512774d63992623e10494c69f",
    };
    dispatch(login(mock));
  };

  return (
    <>
      <ButtonGroup variant="contained" aria-label="signup or login">
        <Button>Signup</Button>
        <Button onClick={onLogin} endIcon={<LoginIcon />}>
          Login
        </Button>
      </ButtonGroup>
    </>
  );
}
