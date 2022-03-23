import React, { useEffect, useState } from "react";
import { useSelector, useDispatch } from "react-redux";
import { WebVault } from "sos-wasm";
import { useNavigate, useParams } from "react-router-dom";

import Typography from "@mui/material/Typography";
import Link from "@mui/material/Link";
import Divider from "@mui/material/Divider";
import Button from "@mui/material/Button";
import ToggleButton from "@mui/material/ToggleButton";
import Snackbar from "@mui/material/Snackbar";
import Alert from "@mui/material/Alert";

import LockIcon from "@mui/icons-material/Lock";
import LockOpenIcon from "@mui/icons-material/LockOpen";

import { VaultWorker } from "./worker";
import { WorkerContext } from "./worker-provider";
import { vaultsSelector, VaultStorage, updateVault } from "./store/vaults";
import SecretList from "./secret-list";
import UnlockVaultForm from './unlock-vault-form';
import { UnlockVaultResult } from "./types";

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
  const { vault, uuid, label } = storage;
  const [invalid, setInvalid] = useState(false);
  const dispatch = useDispatch();

  const onFormSubmit = async (result: UnlockVaultResult) => {
    const {password} = result;
    try {
      // FIXME: put the metaData in storage
      const metaData = await vault.unlock(password);

      const newStorage = {...storage, locked: false};
      dispatch(updateVault(newStorage));
    } catch (e) {
      setInvalid(true);
    }
  }

  const hideInvalid = () => setInvalid(false);

  return (
    <>
      <VaultHeader worker={worker} storage={storage} />
      <UnlockVaultForm worker={worker} onFormSubmit={onFormSubmit} />
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
  const { vault, label, uuid } = storage;
  return (
    <>
      <Typography variant="h3" gutterBottom component="div">
        {label}
      </Typography>
      <Typography variant="h6" gutterBottom component="div">
        {uuid}
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
      const newStorage = {...storage, locked: true};
      dispatch(updateVault(newStorage));
    }
  }

  const ToggleLock = () => (
    <ToggleButton
      value="lock"
      selected={vaultLocked}
      disabled={vaultLocked}
      onChange={setLockState}>
      { vaultLocked ? <LockIcon /> : <LockOpenIcon /> }
    </ToggleButton>
  );

  return locked
    ? <>
      <ToggleLock />
    </>
    : <>
      <Button variant="contained" onClick={(e) => download(e)}>
        Download
      </Button>
      <ToggleLock />
      <Divider />
    </>;
}

function VaultUnlocked(props: VaultViewProps) {
  const { worker, storage } = props;
  const { vault } = storage;
  const [secrets, setSecrets] = useState(null);

  useEffect(() => {
    const getSecretsMeta = async () => {
      const secrets = await vault.getSecretIndex();
      const secretsMap = new Map(Object.entries(secrets));
      console.log("loaded secrets", secretsMap);
      setSecrets(() => secretsMap);
    };
    getSecretsMeta();
  }, [storage]);

  return (
    <>
      <VaultHeader worker={worker} storage={storage} />
      <SecretList worker={worker} secrets={secrets} />
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
          return storage.locked
            ? <VaultLocked worker={worker} storage={storage} />
            : <VaultUnlocked worker={worker} storage={storage} />;
        }}
      </WorkerContext.Consumer>
    </>
  );
}
