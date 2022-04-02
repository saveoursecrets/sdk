import React, { useState } from "react";

import Stack from "@mui/material/Stack";
import Button from "@mui/material/Button";
import IconButton from "@mui/material/IconButton";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";

import AddIcon from "@mui/icons-material/Add";
import RemoveIcon from "@mui/icons-material/RemoveCircleOutline";

import { Credentials, KeyValueError, CredentialsResult } from "../../types";

import KeyValueSecret from "./key-value-secret";

interface CredentialsFormProps extends CredentialsResult {
  onFormSubmit: (result: CredentialsResult) => void;
}

function mapErrors(
  credentials: [string, string][]
): [boolean, KeyValueError[]] {
  let hasCredError = false;
  const errors = credentials.map((item: [string, string]) => {
    const [key, value] = item;
    let error = { key: false, value: false };
    if (key.trim() === "") {
      error.key = true;
      hasCredError = true;
    }
    if (value.trim() === "") {
      error.value = true;
      hasCredError = true;
    }
    return error;
  });

  return [hasCredError, errors];
}

export default function CredentialsForm(props: CredentialsFormProps) {
  const { onFormSubmit } = props;
  const [label, setLabel] = useState(props.label);
  const [labelError, setLabelError] = useState(false);

  const [credentials, setCredentials] = useState(
    Object.entries(props.credentials)
  );

  const [credentialsErrors, setCredentialsErrors] = useState(
    credentials.map(() => ({ key: false, value: false }))
  );

  const onLabelChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setLabel(e.target.value);

  const addCredential = () => {
    console.log("Credentials before add", credentials);
    const creds = [...credentials];
    creds.unshift(["", ""]);
    setCredentials(creds);

    const credsErrors = [...credentialsErrors];
    credsErrors.unshift({ key: false, value: false });
    setCredentialsErrors(credsErrors);
  };

  const removeCredential = (index: number) => {
    const creds = [...credentials];
    creds.splice(index, 1);
    setCredentials(creds);

    const credsErrors = [...credentialsErrors];
    credsErrors.splice(index, 1);
    setCredentialsErrors(credsErrors);
  };

  const onSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    setLabelError(false);
    setCredentialsErrors([]);

    const [hasError, credErrors] = mapErrors(credentials);

    if (label.trim() === "") {
      setLabelError(true);
      setLabel("");
    } else if (hasError) {
      setCredentialsErrors(credErrors);
    } else {
      const map = credentials.reduce(
        (out: Credentials, item: [string, string]) => {
          const [key, value] = item;
          out[key] = value;
          return out;
        },
        {}
      );

      onFormSubmit({ label, credentials: map });
    }
  };

  return (
    <form id="credentials-form" onSubmit={onSubmit} noValidate>
      <Stack spacing={2} sx={{ paddingTop: 1 }}>
        <TextField
          id="secret-label"
          label="Name"
          placeholder="Enter a secret name"
          required
          autoFocus
          onChange={onLabelChange}
          value={label}
          error={labelError}
        />
        <Button onClick={addCredential} startIcon={<AddIcon />}>
          Add Credential
        </Button>
        {credentials.map((item: [string, string], index) => {
          const [name, value] = item;
          const error = credentialsErrors[index] || {
            key: false,
            value: false,
          };

          console.log("render cred", name, value);

          const onChange = (index: number, key: string, value: string) => {
            const creds = [...credentials];
            creds[index] = [key, value];
            setCredentials(creds);
          };

          return (
            <Stack key={index} direction="row" spacing={2} alignItems="center">
              <KeyValueSecret
                onChange={onChange}
                error={error}
                name={name}
                value={value}
                index={index}
              />
              <IconButton
                disabled={credentials.length === 1}
                sx={{ width: 40, height: 40 }}
                onClick={() => removeCredential(index)}
              >
                <RemoveIcon />
              </IconButton>
            </Stack>
          );
        })}
      </Stack>
    </form>
  );
}
