import * as React from "react";
import Button from "@mui/material/Button";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogTitle from "@mui/material/DialogTitle";

import FileUploadForm from "../forms/file-upload";

import { SecretInfo } from "../../types";

interface FileUploadProps {
  open: boolean;
  handleCancel: () => void;
  handleOk: (result: SecretInfo) => void;
}

export default function FileUploadDialog(props: FileUploadProps) {
  const { open, handleCancel, handleOk } = props;

  return (
    <Dialog open={open} onClose={handleCancel}>
      <DialogTitle color="text.secondary">File Upload</DialogTitle>
      <DialogContent>
        <FileUploadForm onFormSubmit={handleOk} />
      </DialogContent>
      <DialogActions>
        <Button onClick={handleCancel}>Cancel</Button>
        <Button type="submit" form="file-upload-form" variant="contained">
          OK
        </Button>
      </DialogActions>
    </Dialog>
  );
}
