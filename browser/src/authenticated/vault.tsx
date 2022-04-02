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

import LockIcon from "@mui/icons-material/Lock";
import LockOpenIcon from "@mui/icons-material/LockOpen";

import { WorkerContext } from "../worker-provider";
import {
  vaultsSelector,
  VaultStorage,
  updateVault,
  loadVaults,
} from "../store/vaults";
import { userSelector } from "../store/user";

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

interface VaultViewProps {
  worker: VaultWorker;
  storage: VaultStorage;
}

function VaultLocked(props: VaultViewProps) {
  const { worker, storage } = props;
  const { vault } = storage;
  const [invalid, setInvalid] = useState(false);
  const dispatch = useDispatch();

  const onFormSubmit = async (result: UnlockVaultResult) => {
    const { password } = result;
    try {
      // FIXME: put the metaData in storage
      const metaData = await vault.unlock(password);

      const newStorage = { ...storage, locked: false };
      dispatch(updateVault(newStorage));
    } catch (e) {
      setInvalid(true);
    }
  };

  const hideInvalid = () => setInvalid(false);

  return (
    <>
      <VaultHeader worker={worker} storage={storage} />
      <Grid
        container
        direction="column"
        justifyContent="center"
        alignItems="center"
      >
        <UnlockVaultForm onFormSubmit={onFormSubmit} />
        <Button type="submit" form="unlock-vault-form" variant="contained">
          Unlock
        </Button>
      </Grid>
      <Snackbar open={invalid} autoHideDuration={6000} onClose={hideInvalid}>
        <Alert onClose={hideInvalid} severity="error">
          Invalid password
        </Alert>
      </Snackbar>
    </>
  );
}

function VaultHeader(props: VaultViewProps) {
  const { worker, storage } = props;
  const { label } = storage;
  return (
    <>
      <Typography variant="h3" gutterBottom component="div">
        {label}
      </Typography>
      <VaultActions worker={worker} storage={storage} />
    </>
  );
}

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

  return locked ? (
    <>
      <ToggleLock />
    </>
  ) : (
    <>
      <Button variant="contained" onClick={(e) => download(e)}>
        Download
      </Button>
      <ToggleLock />
      <Divider />
    </>
  );
}

function VaultUnlocked(props: VaultViewProps) {
  const { worker, storage } = props;
  const { vault } = storage;
  const dispatch = useDispatch();

  const createNewSecret = (kind: SecretKind) => {
    console.log("create new secret", kind);
    switch (kind) {
      case SecretKind.Account:
        dispatch(setDialogVisible([NEW_ACCOUNT_PASSWORD, true]));
        break;
      case SecretKind.Note:
        dispatch(setDialogVisible([NEW_SECURE_NOTE, true]));
        break;
      case SecretKind.Credentials:
        dispatch(setDialogVisible([NEW_CREDENTIALS, true]));
        break;
      case SecretKind.File:
        dispatch(setDialogVisible([NEW_FILE_UPLOAD, true]));
        break;
    }
  };

  return (
    <>
      <VaultHeader worker={worker} storage={storage} />
      <SecretList worker={worker} storage={storage} />
      <NewSecretDial onSelect={createNewSecret} />
    </>
  );
}

export default function Vault() {
  const params = useParams();
  const { id } = params;
  const { vaults } = useSelector(vaultsSelector);

  const storage = vaults.find((v) => v.uuid === id);

  if (!storage) {
    return <p>Vault not found</p>;
  }

  return (
    <>
      <WorkerContext.Consumer>
        {(worker) => {
          return storage.locked ? (
            <VaultLocked worker={worker} storage={storage} />
          ) : (
            <VaultUnlocked worker={worker} storage={storage} />
          );
        }}
      </WorkerContext.Consumer>
    </>
  );
}
