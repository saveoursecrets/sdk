import React from "react";
import { useDispatch, useSelector } from "react-redux";
import { useNavigate } from "react-router-dom";

import { Tooltip, Badge, Button, Stack } from "@mui/material";
import LogoutIcon from "@mui/icons-material/Logout";
import SyncIcon from "@mui/icons-material/Sync";

import { logout } from "../store/account";
import { vaultsSelector, lockAll, syncChangeSet } from "../store/vaults";
import { accountSelector } from "../store/account";
import { batchSelector } from "../store/batch";
import { AppDispatch } from "../store";

import { WorkerProps } from "../props";

export default function AppBarActions(props: WorkerProps) {
  const { worker } = props;
  const { account } = useSelector(accountSelector);
  const { vaults } = useSelector(vaultsSelector);
  const { totalChanges, changeSet } = useSelector(batchSelector);
  const dispatch: AppDispatch = useDispatch();
  const navigate = useNavigate();

  const onLogout = () => {
    dispatch(lockAll(vaults));
    dispatch(logout());
    navigate("/");
  };

  const trySyncChanges = async () => {
    console.log("try to sync unsaved changes...");
    await dispatch(syncChangeSet({ account, worker, changeSet }));
  };

  console.log("got batch changeSet", totalChanges);

  const syncChip =
    totalChanges !== 0 ? (
      <Tooltip title="Sync Changes">
        <Badge
          color="warning"
          badgeContent={totalChanges}
          anchorOrigin={{ vertical: "top", horizontal: "left" }}
        >
          <Button
            color="warning"
            variant="contained"
            startIcon={<SyncIcon />}
            onClick={trySyncChanges}
          >
            Sync
          </Button>
        </Badge>
      </Tooltip>
    ) : null;

  return (
    <Stack direction="row" spacing={2}>
      {syncChip}
      <Tooltip title="Logout">
        <Button variant="contained" onClick={onLogout} endIcon={<LogoutIcon />}>
          Logout
        </Button>
      </Tooltip>
    </Stack>
  );
}
