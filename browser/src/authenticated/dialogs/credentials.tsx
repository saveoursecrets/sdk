import * as React from "react";
import Button from "@mui/material/Button";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogTitle from "@mui/material/DialogTitle";

import CredentialsForm from "../forms/credentials";

import { SecretInfo } from "../../types";

interface CredentialsProps {
  open: boolean;
  handleCancel: () => void;
  handleOk: (result: SecretInfo) => void;
}

export default function CredentialsDialog(props: CredentialsProps) {
  const { open, handleCancel, handleOk } = props;

  return (
    <Dialog open={open} onClose={handleCancel}>
      <DialogTitle color="text.secondary">Credentials List</DialogTitle>
      <DialogContent>
        <CredentialsForm onFormSubmit={handleOk} />
      </DialogContent>
      <DialogActions>
        <Button onClick={handleCancel}>Cancel</Button>
        <Button type="submit" form="credentials-form" variant="contained">
          OK
        </Button>
      </DialogActions>
    </Dialog>
  );
}
