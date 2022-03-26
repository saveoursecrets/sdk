import React, { useState } from "react";

import Stack from "@mui/material/Stack";
import TextField from "@mui/material/TextField";

import Diceware from "../../diceware";
import { NewVaultResult } from "../../types";

interface CreateVaultProps {
  onFormSubmit: (result: NewVaultResult) => void;
}

export default function CreateVaultForm(props: CreateVaultProps) {
  const { onFormSubmit } = props;

  const [label, setLabel] = useState("");
  const [labelError, setLabelError] = useState(false);
  const [labelHelperText, setLabelHelperText] = useState("");

  const [password, setPassword] = useState("");

  const onLabelChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setLabel(e.target.value);

  const onSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    setLabelHelperText("");
    setLabelError(false);

    if (label.trim() === "") {
      setLabelHelperText("Label may not be empty");
      setLabelError(true);
      setLabel("");
    } else {
      onFormSubmit({ label, password });
    }
  };

  const onGenerate = (passphrase: string) => {
    setPassword(passphrase);
  };

  return (
    <form id="new-vault-form" onSubmit={onSubmit}>
      <Stack spacing={2} sx={{paddingTop: 1}}>
        <TextField
          id="vault-label"
          label="Label"
          autoFocus
          onChange={onLabelChange}
          value={label}
          error={labelError}
          helperText={labelHelperText}
          variant="outlined"
          placeholder="Label for the new vault"
        />
        <Diceware onGenerate={onGenerate} />
      </Stack>
    </form>
  );
}
