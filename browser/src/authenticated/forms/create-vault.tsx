import React, { useState } from "react";

import Stack from "@mui/material/Stack";
import TextField from "@mui/material/TextField";

import Diceware from "../../diceware";
import { NewVaultResult, VaultWorker } from "../../types";

interface CreateVaultProps {
  worker: VaultWorker;
  onFormSubmit: (result: NewVaultResult) => void;
}

export default function CreateVaultForm(props: CreateVaultProps) {
  const { worker } = props;
  const { onFormSubmit } = props;

  const [name, setName] = useState("");
  const [nameError, setNameError] = useState(false);
  const [nameHelperText, setNameHelperText] = useState("");

  const [label, setLabel] = useState("");
  const [labelError, setLabelError] = useState(false);
  const [labelHelperText, setLabelHelperText] = useState("");

  const [password, setPassword] = useState("");

  const onNameChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setName(e.target.value);

  const onLabelChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setLabel(e.target.value);

  const onSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    setNameHelperText("");
    setNameError(false);

    setLabelHelperText("");
    setLabelError(false);

    if (name.trim() === "") {
      setNameHelperText("Name may not be empty");
      setNameError(true);
      setName("");
    } else if (label.trim() === "") {
      setLabelHelperText("Label may not be empty");
      setLabelError(true);
      setLabel("");
    } else {
      onFormSubmit({ label, name, password });
    }
  };

  const onGenerate = (passphrase: string) => setPassword(passphrase);

  return (
    <form id="new-vault-form" onSubmit={onSubmit}>
      <Stack spacing={2} sx={{ paddingTop: 1 }}>
        <TextField
          id="vault-name"
          label="Name"
          autoFocus
          onChange={onNameChange}
          value={name}
          error={nameError}
          helperText={nameHelperText}
          variant="outlined"
          placeholder="Public name for the vault"
        />

        <TextField
          id="vault-label"
          label="Label"
          onChange={onLabelChange}
          value={label}
          error={labelError}
          helperText={labelHelperText}
          variant="outlined"
          placeholder="Private label for the vault"
        />
        <Diceware onGenerate={onGenerate} worker={worker} />
      </Stack>
    </form>
  );
}
