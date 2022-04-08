import React, { useState } from "react";
import { useDispatch } from "react-redux";

import Button from "@mui/material/Button";
import Snackbar from "@mui/material/Snackbar";
import Alert from "@mui/material/Alert";
import Stack from "@mui/material/Stack";

import { VaultStorage, updateVault } from "../store/vaults";

import { UnlockVaultResult, VaultWorker } from "../types";
import UnlockVaultForm from "./unlock-vault-form";

type VaultViewProps = {
  worker: VaultWorker;
  storage: VaultStorage;
};

export default function UnlockVault(props: VaultViewProps) {
  const { storage } = props;
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
      <Stack spacing={2} padding={2}>
        <UnlockVaultForm onFormSubmit={onFormSubmit} />
        <Button type="submit" form="unlock-vault-form" variant="contained">
          Unlock
        </Button>
      </Stack>
      <Snackbar open={invalid} autoHideDuration={6000} onClose={hideInvalid}>
        <Alert onClose={hideInvalid} severity="error">
          Invalid password
        </Alert>
      </Snackbar>
    </>
  );
}
