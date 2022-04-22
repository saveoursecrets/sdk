import React from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from 'react-router-dom';

import Tooltip from "@mui/material/Tooltip";
import Button from "@mui/material/Button";
import LogoutIcon from "@mui/icons-material/Logout";

import { logout } from "../store/account";
import { vaultsSelector, lockAll } from "../store/vaults";

export default function AppBarActions() {
  const { vaults } = useSelector(vaultsSelector);
  const dispatch = useDispatch();
  const navigate = useNavigate();

  const onLogout = () => {
    dispatch(lockAll(vaults));
    dispatch(logout());
    navigate("/");
  };

  return (
    <>
      <Tooltip title="Logout">
        <Button variant="contained" onClick={onLogout} endIcon={<LogoutIcon />}>
          Logout
        </Button>
      </Tooltip>
    </>
  );
}
