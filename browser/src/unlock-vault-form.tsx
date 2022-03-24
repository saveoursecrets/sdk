import React, { useState } from "react";
import { WebVault } from "sos-wasm";

import { VaultWorker } from "./worker";
import { WorkerContext } from "./worker-provider";
import { vaultsSelector, addVault } from "./store/vaults";

import Stack from "@mui/material/Stack";
import Button from "@mui/material/Button";
import TextField from "@mui/material/TextField";
import FormHelperText from "@mui/material/FormHelperText";

import { UnlockVaultResult } from "./types";

interface UnlockVaultProps {
  worker: VaultWorker;
  onFormSubmit: (result: UnlockVaultResult) => void;
}

export default function UnlockVaultForm(props: UnlockVaultProps) {
  const { worker, onFormSubmit } = props;

  const [password, setPassword] = useState("");
  const [passwordError, setPasswordError] = useState(false);
  const [passwordHelperText, setPasswordHelperText] = useState("");

  const onPasswordChange = (e: any) => setPassword(e.target.value);

  const onSubmit = (e: any) => {
    e.preventDefault();

    setPasswordHelperText("");
    setPasswordError(false);

    if (password === "") {
      setPasswordHelperText("Password may not be empty");
      setPasswordError(true);
    } else {
      onFormSubmit({ password });
    }
  };

  return (
    <form id="unlock-vault-form" onSubmit={onSubmit}>
      <Stack spacing={2}>
        <TextField
          id="vault-password"
          type="password"
          autoComplete="off"
          label="Password"
          onChange={onPasswordChange}
          value={password}
          error={passwordError}
          helperText={passwordHelperText}
          variant="outlined"
        />
      </Stack>
    </form>
  );
}
