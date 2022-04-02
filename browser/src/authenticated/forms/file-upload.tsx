import React, { useState } from "react";

import Button from "@mui/material/Button";
import Stack from "@mui/material/Stack";
import TextField from "@mui/material/TextField";
import Input from "@mui/material/Input";

import { FileUploadResult } from "../../types";

// 8MB for file uploads
const MAX_FILE_SIZE = 8388608;

/*
interface FileInfo {
  name?: string;
  size?: number;
  buffer: ArrayBuffer;
}
*/

interface FileUploadFormProps extends FileUploadResult {
  onFormSubmit: (result: FileUploadResult) => void;
}

export default function FileUploadForm(props: FileUploadFormProps) {
  const { onFormSubmit } = props;
  const [label, setLabel] = useState(props.label);
  const [labelError, setLabelError] = useState(false);

  const [file, setFile] = useState({
    buffer: props.buffer,
    name: null,
    size: null,
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
      onFormSubmit({ label, buffer, name });
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
