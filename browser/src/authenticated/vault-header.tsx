import React from "react";

import Typography from "@mui/material/Typography";
import Divider from "@mui/material/Divider";
import Button from "@mui/material/Button";
import Box from "@mui/material/Box";

//import LockIcon from "@mui/icons-material/Lock";
//import LockOpenIcon from "@mui/icons-material/LockOpen";

import { VaultStorage } from "../store/vaults";

import { VaultWorker } from "../types";

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
