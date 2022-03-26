import React, { useState } from "react";

import Stack from "@mui/material/Stack";
import TextField from "@mui/material/TextField";
import Typography from "@mui/material/Typography";

import { SecureNoteResult } from "../../types";

interface SecureNoteFormProps {
  label: string;
  note: string;
  onFormSubmit: (result: SecureNoteResult) => void;
}

export default function SecureNoteForm(props: SecureNoteFormProps) {
  const { onFormSubmit } = props;
  const [label, setLabel] = useState(props.label);
  const [labelError, setLabelError] = useState(false);

  const [note, setNote] = useState(props.note);
  const [noteError, setNoteError] = useState(false);

  const onLabelChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setLabel(e.target.value);

  const onNoteChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setNote(e.target.value);

  const onSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    setLabelError(false);
    setNoteError(false);

    if (label.trim() === "") {
      setLabelError(true);
      setLabel("");
    } else if (note.trim() === "") {
      setNoteError(true);
      setNote("");
    } else {
      onFormSubmit({ label, note });
    }
  };

  return (
    <form id="secure-note-form" onSubmit={onSubmit} noValidate>
      <Stack spacing={2}>
        <Typography variant="h4" color="text.secondary">
          Secure Note
        </Typography>
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
        <TextField
          id="secure-note"
          label="Note"
          placeholder="Enter a note"
          required
          multiline
          rows={6}
          onChange={onNoteChange}
          value={note}
          error={noteError}
        />
      </Stack>
    </form>
  );
}
