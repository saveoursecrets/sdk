import React, { useState } from "react";

import Stack from "@mui/material/Stack";
import TextField from "@mui/material/TextField";

interface ConfirmValueFormProps {
  value: string;
  onFormSubmit: () => void;
}

export default function ConfirmValueForm(props: ConfirmValueFormProps) {
  const { value, onFormSubmit } = props;
  const [label, setLabel] = useState("");
  const [labelError, setLabelError] = useState(false);

  const onLabelChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setLabel(e.target.value);

  const onSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    setLabelError(false);

    if (label.trim() === "" || label !== value) {
      setLabelError(true);
    } else {
      onFormSubmit();
    }
  };

  return (
    <form id="confirm-value-form" onSubmit={onSubmit} noValidate>
      <Stack>
        <TextField
          id="confirm-value"
          label="Name"
          placeholder="Enter the name to confirm"
          required
          autoFocus
          onChange={onLabelChange}
          value={label}
          error={labelError}
        />
      </Stack>
    </form>
  );
}
