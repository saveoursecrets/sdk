import React, { useState } from "react";
import { useSelector, useDispatch } from "react-redux";
import { useParams } from "react-router-dom";

import Typography from "@mui/material/Typography";
import Divider from "@mui/material/Divider";
import Button from "@mui/material/Button";
import ToggleButton from "@mui/material/ToggleButton";
import Snackbar from "@mui/material/Snackbar";
import Alert from "@mui/material/Alert";
import Grid from "@mui/material/Grid";
import Box from "@mui/material/Box";

import LockIcon from "@mui/icons-material/Lock";
import LockOpenIcon from "@mui/icons-material/LockOpen";

import {
  vaultsSelector,
  VaultStorage,
  updateVault,
  loadVaults,
} from "../store/vaults";
import { userSelector } from "../store/user";

import { WorkerContext } from "../worker-provider";
import { SecretKind, UnlockVaultResult, VaultWorker } from "../types";
import SecretList from "./secret-list";
import UnlockVaultForm from "./unlock-vault-form";
import NewSecretDial from "./new-secret-dial";

import {
  setDialogVisible,
  NEW_SECURE_NOTE,
  NEW_ACCOUNT_PASSWORD,
  NEW_CREDENTIALS,
  NEW_FILE_UPLOAD,
} from "../store/dialogs";

function downloadVault(fileName: string, buffer: Uint8Array) {
  const blob = new Blob([buffer], { type: "application/octet-stream" });
  const link = document.createElement("a");
  link.href = window.URL.createObjectURL(blob);
  link.download = fileName;
  link.click();
}

type VaultViewProps = {
  worker: VaultWorker;
  storage: VaultStorage;
};

function VaultActions(props: VaultViewProps) {
  const { storage } = props;
  const { vault, uuid, locked } = storage;
  const [vaultLocked, setVaultLocked] = useState(locked);
  const dispatch = useDispatch();

  const download = async (e: React.MouseEvent<HTMLElement>) => {
    e.preventDefault();
    const buffer = await vault.buffer();
    downloadVault(`${uuid}.vault`, buffer);
  };

  /*
  const setLockState = async () => {
    if (!vaultLocked) {
      await vault.lock();
      setVaultLocked(true);
      const newStorage = { ...storage, locked: true };
      dispatch(updateVault(newStorage));
    }
  };

  const ToggleLock = () => (
    <ToggleButton
      value="lock"
      selected={vaultLocked}
      disabled={vaultLocked}
      onChange={setLockState}
    >
      {vaultLocked ? <LockIcon /> : <LockOpenIcon />}
    </ToggleButton>
  );
  */

  return locked ? (
    <></>
  ) : (
    <>
      <Button variant="contained" onClick={(e) => download(e)}>
        Download
      </Button>
    </>
  );
}

export default function VaultHeader(props: VaultViewProps) {
  const { worker, storage } = props;
  const { label } = storage;
  return (
    <>
      <Box padding={2}>
        <Typography variant="h3" gutterBottom component="div">
          {label}
        </Typography>
        <VaultActions worker={worker} storage={storage} />
      </Box>
      <Divider />
    </>
  );
}
