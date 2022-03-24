import React, { useState } from "react";

import Stack from "@mui/material/Stack";
import TextField from "@mui/material/TextField";

import { UnlockVaultResult } from "./types";

interface UnlockVaultProps {
  onFormSubmit: (result: UnlockVaultResult) => void;
}

export default function UnlockVaultForm(props: UnlockVaultProps) {
  const { onFormSubmit } = props;
  const [password, setPassword] = useState("");
  const [passwordError, setPasswordError] = useState(false);
  const [passwordHelperText, setPasswordHelperText] = useState("");

  const onPasswordChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setPassword(e.target.value);

  const onSubmit = (e: React.FormEvent<HTMLFormElement>) => {
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
