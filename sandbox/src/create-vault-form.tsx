import React, { useState } from "react";
import { useSelector, useDispatch } from "react-redux";
import { WebVault } from "sos-wasm";
import { useNavigate } from "react-router-dom";

import { VaultWorker } from "./worker";
import { WorkerContext } from "./worker-provider";
import { vaultsSelector, addVault } from "./store/vaults";

import Stack from "@mui/material/Stack";
import Button from "@mui/material/Button";
import TextField from "@mui/material/TextField";
import FormHelperText from "@mui/material/FormHelperText";

import { NewVaultForm } from "./types";

interface CreateVaultProps {
  worker: VaultWorker;
  onFormSubmit: (result: NewVaultForm) => void;
}

export default function CreateVaultForm(props: CreateVaultProps) {
  const { worker, onFormSubmit } = props;
  const dispatch = useDispatch();
  const navigate = useNavigate();

  const [label, setLabel] = useState("");
  const [labelError, setLabelError] = useState(false);
  const [labelHelperText, setLabelHelperText] = useState("");

  const [password, setPassword] = useState("");
  const [passwordError, setPasswordError] = useState(false);
  const [passwordHelperText, setPasswordHelperText] = useState("");

  const onLabelChange = (e: any) => setLabel(e.target.value);
  const onPasswordChange = (e: any) => setPassword(e.target.value);

  const onSubmit = (e: any) => {
    e.preventDefault();

    setLabelHelperText("");
    setLabelError(false);
    setPasswordHelperText("");
    setPasswordError(false);

    if (label.trim() === "") {
      setLabelHelperText("Label may not be empty");
      setLabelError(true);
      setLabel("");
    } else if (password.trim() === "") {
      setPasswordHelperText("Password may not be empty");
      setPasswordError(true);
      setPassword("");
    } else if (password.length < 12) {
      setPasswordHelperText("Password is too short");
      setPasswordError(true);
    } else {
      //createVault(label, password);
      onFormSubmit({ label, password });
    }
  };

  return (
    <form id="new-vault-form" onSubmit={onSubmit}>
      <Stack spacing={2}>
        <TextField
          id="vault-label"
          label="Label"
          onChange={onLabelChange}
          value={label}
          error={labelError}
          helperText={labelHelperText}
          variant="outlined"
        />
        <FormHelperText>
          Choose a label for your new vault; the label is private and only shown
          to you.
        </FormHelperText>

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
        <FormHelperText>
          Your password must be at least 12 characters; your secrets are safer
          with a strong password so combine letters, numbers and other
          characters.
        </FormHelperText>
      </Stack>
    </form>
  );
}
