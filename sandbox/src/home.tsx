import React, { useState } from 'react';
import { useSelector, useDispatch } from "react-redux";
import { WebVault } from 'sos-wasm';
import { useNavigate } from 'react-router-dom';

import { VaultWorker } from './worker';
import { WorkerContext } from "./worker-provider";
import { vaultsSelector, addVault } from './store/vaults';

import Stack from '@mui/material/Stack';
import Button from '@mui/material/Button';
import TextField from '@mui/material/TextField';
import FormHelperText from '@mui/material/FormHelperText';

interface CreateVaultProps {
  worker: VaultWorker;
}

function CreateVault(props: CreateVaultProps) {
  const {worker} = props;
  const dispatch = useDispatch();
  const navigate = useNavigate();

  const [label, setLabel] = useState("");
  const [labelError, setLabelError] = useState(false);
  const [labelHelperText, setLabelHelperText] = useState("");

  const [password, setPassword] = useState("");
  const [passwordError, setPasswordError] = useState(false);
  const [passwordHelperText, setPasswordHelperText] = useState("");

  const createVault = async (label: string, password: string) => {
    const passphrase = await worker.keccak256(password);
    //const encoder = new TextEncoder();
    //const passwordBuffer = encoder.encode(passphrase);
    const vault: WebVault = await new (worker.WebVault as any)();
    await vault.initialize(label, Array.from(passphrase));
    const uuid = await vault.id();
    const storage = {uuid, vault, label, locked: false};
    dispatch(addVault(storage))
    navigate(`/vault/${uuid}`);
  }

  const onLabelChange = (e: any) => setLabel(e.target.value);
  const onPasswordChange = (e: any) => setPassword(e.target.value);

  const onSubmit = (e: any) => {
    e.preventDefault();
    if (label.trim() === "") {
      setLabelHelperText("Label may not be empty")
      setLabelError(true);
      setLabel("");
    } else if (password.trim() === "") {
      setPasswordHelperText("Password may not be empty")
      setPasswordError(true);
      setPassword("");
    } else if (password.length < 12) {
      setPasswordHelperText("Password is too short")
      setPasswordError(true);
    } else {
      console.log("submit form...", label);
      console.log("submit form...", password);
      createVault(label, password);
    }
  }

  return <form onSubmit={onSubmit}>
    <Stack spacing={2}>
      <FormHelperText>Choose a label for your new vault; the label is private and only shown to you.</FormHelperText>
      <TextField
        required
        id="vault-label"
        label="Label"
        onChange={onLabelChange}
        value={label}
        error={labelError}
        helperText={labelHelperText}
        variant="outlined"
      />

      <FormHelperText>Your password must be at least 12 characters; your secrets are safer with a strong password so combine letters, numbers and other characters.</FormHelperText>
      <TextField
        required
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
      <Button type="submit" variant="contained">Create vault</Button>
    </Stack>
  </form>;
}

export default function Home() {
  return <>
    <WorkerContext.Consumer>
      {(worker) => {
        return (
          <CreateVault
            worker={worker}
          />
        );
      }}
    </WorkerContext.Consumer>
  </>;
}
