import React, { useState } from "react";

import Stack from "@mui/material/Stack";
import TextField from "@mui/material/TextField";

import ViewablePassword from "./viewable-password";
import { KeyValueError } from "../../types";

interface KeyValueSecretProps {
  index: number;
  error: KeyValueError;
  onChange: (index: number, key: string, value: string) => void;
  initialName: string;
  initialValue: string;
}

export default function KeyValueSecret(props: KeyValueSecretProps) {
  const { index, error, onChange, initialName, initialValue } = props;

  const [key, setKey] = useState(initialName || "");
  const [value, setValue] = useState(initialValue || "");

  const onKeyChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setKey(e.target.value);
    onChange(index, e.target.value, value);
  };

  const onValueChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setValue(e.target.value);
    onChange(index, key, e.target.value);
  };

  return (
    <Stack direction="row" justifyContent="space-between" spacing={2}>
      <TextField
        id={`key${index}`}
        label="Key"
        placeholder="Enter a key"
        required
        value={key}
        onChange={onKeyChange}
        error={error.key}
      />

      <ViewablePassword
        id={`value${index}`}
        label="Value"
        placeholder="Enter a value"
        value={value}
        onChange={onValueChange}
        error={error.value}
      />
    </Stack>
  );
}
