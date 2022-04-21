import React from "react";
import { useNavigate } from "react-router-dom";

import { ButtonGroup, Button } from "@mui/material";

import LoginIcon from "@mui/icons-material/Login";

export default function AppBarActions() {
  const navigate = useNavigate();

  const onLogin = () => {
    navigate("/login");
  };

  const signup = () => {
    navigate("/signup");
  };

  return (
    <>
      <ButtonGroup variant="contained" aria-label="signup or login">
        <Button onClick={signup}>Signup</Button>
        <Button onClick={onLogin} endIcon={<LoginIcon />}>
          Login
        </Button>
      </ButtonGroup>
    </>
  );
}
