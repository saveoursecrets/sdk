import React, { useState } from "react";

import Button from "@mui/material/Button";
import Stack from "@mui/material/Stack";
import TextField from "@mui/material/TextField";
import Input from "@mui/material/Input";

import { SecretData, SecretKind, FileSecret } from "../../types";

// 8MB for file uploads
const MAX_FILE_SIZE = 8388608;

/*
interface FileInfo {
  name?: string;
  size?: number;
  buffer: ArrayBuffer;
}
*/

interface FileUploadFormProps {
  onFormSubmit: (result: SecretData) => void;
  secret?: SecretData;
}

export default function FileUploadForm(props: FileUploadFormProps) {
  const { onFormSubmit, secret } = props;

  const initialLabel = secret && secret.meta.label;
  const initialBuffer = secret && (secret.secret as FileSecret).buffer;
  const initialMime = secret && (secret.secret as FileSecret).mime;

  const [mime, setMime] = useState(initialMime);

  const [label, setLabel] = useState(initialLabel || "");
  const [labelError, setLabelError] = useState(false);

  const [file, setFile] = useState({
    buffer: initialBuffer || null,
    name: null,
    size: (initialBuffer && initialBuffer.length) || null,
  });
  const [fileError, setFileError] = useState(false);

  const onLabelChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setLabel(e.target.value);

  const onFileChange = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files[0];
    const { name, size } = file;
    if (size <= MAX_FILE_SIZE) {
      const buffer = await file.arrayBuffer();
      setFile({ name, size, buffer: Array.from(new Uint8Array(buffer)) });

      // Clear any previously set mime type
      // so the webassembly can try to guess the mime
      setMime(null);

      if (label === "") {
        setLabel(name);
      }
    } else {
      // TODO: handle too large file error gracefully
      setFileError(true);
    }
  };

  const onSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    setLabelError(false);
    setFileError(false);

    console.log("submit", file);

    if (label.trim() === "") {
      setLabelError(true);
      setLabel("");
    } else if (!file.buffer) {
      setFileError(true);
    } else {
      const { buffer, name } = file;

      console.log("submit file", buffer.length);

      const info: SecretData = {
        secretId: secret && secret.secretId,
        meta: {
          label,
          kind: SecretKind.File,
        },
        secret: { buffer, name, mime },
      };
      onFormSubmit(info);
    }
  };

  return (
    <form id="file-upload-form" onSubmit={onSubmit} noValidate>
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
          id="file-name"
          hiddenLabel
          placeholder="Select a file to upload"
          disabled
          onChange={onLabelChange}
          value={file.name || ""}
          error={fileError}
        />
        <label htmlFor="file-upload">
          <Input
            id="file-upload"
            sx={{ display: "none" }}
            onChange={onFileChange}
            type="file"
          />
          <Button variant="contained" component="span">
            Upload
          </Button>
        </label>
      </Stack>
    </form>
  );
}
