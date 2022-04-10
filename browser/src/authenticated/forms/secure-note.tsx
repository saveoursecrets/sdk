import React, { useState } from "react";

import Stack from "@mui/material/Stack";
import TextField from "@mui/material/TextField";

import { SecretData, SecretKind, NoteSecret } from "../../types";

interface SecureNoteFormProps {
  onFormSubmit: (result: SecretData) => void;
  secret?: SecretData;
}

export default function SecureNoteForm(props: SecureNoteFormProps) {
  const { onFormSubmit, secret } = props;

  const initialLabel = secret && secret.meta.label;
  const initialNote = secret && (secret.secret as string);

  const [label, setLabel] = useState(initialLabel || "");
  const [labelError, setLabelError] = useState(false);

  const [note, setNote] = useState(initialNote || "");
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
      const info: SecretData = {
        secretId: secret && secret.secretId,
        meta: {
          label,
          kind: SecretKind.Note,
        },
        secret: note,
      };
      onFormSubmit(info);
    }
  };

  return (
    <form id="secure-note-form" onSubmit={onSubmit} noValidate>
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
