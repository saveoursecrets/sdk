import React from "react";
import { useDispatch, useSelector } from "react-redux";

import Tooltip from "@mui/material/Tooltip";
import Button from "@mui/material/Button";
import LogoutIcon from "@mui/icons-material/Logout";

import { logout } from "../store/user";
import { vaultsSelector, lockAll } from "../store/vaults";

export default function AppBarActions() {
  const { vaults } = useSelector(vaultsSelector);
  const dispatch = useDispatch();

  const onLogout = () => {
    dispatch(lockAll(vaults));
    dispatch(logout());
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
