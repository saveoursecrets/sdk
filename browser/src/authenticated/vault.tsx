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
import VaultHeader from "./vault-header";

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
      const meta = await vault.unlock(password);
      const newStorage = { ...storage, meta, locked: false };
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

function VaultUnlocked(props: VaultViewProps) {
  const { worker, storage } = props;
  return (
    <>
      <VaultHeader worker={worker} storage={storage} />
      <SecretList worker={worker} storage={storage} />
      <NewSecretDial />
    </>
  );
}

export default function Vault() {
  const params = useParams();
  const { vaultId } = params;
  const { vaults } = useSelector(vaultsSelector);

  const storage = vaults.find((v) => v.uuid === vaultId);

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
