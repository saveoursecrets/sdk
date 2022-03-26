import * as React from "react";
import Alert from "@mui/material/Alert";
import Button from "@mui/material/Button";
import Checkbox from "@mui/material/Checkbox";
import FormControlLabel from "@mui/material/FormControlLabel";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogTitle from "@mui/material/DialogTitle";

import SecureNoteForm from "../forms/secure-note";

import { SecureNoteResult } from "../../types";

interface SecureNoteProps {
  open: boolean;
  handleCancel: () => void;
  handleOk: (result: SecureNoteResult) => void;
}

export default function SecureNoteDialog(props: SecureNoteProps) {
  const { open, handleCancel, handleOk } = props;
  const onFormSubmit = (result: SecureNoteResult) => handleOk(result);

  return (
    <Dialog open={open} onClose={handleCancel}>
      <DialogTitle>Secure Note</DialogTitle>
      <DialogContent>
        <SecureNoteForm label="" note="" onFormSubmit={onFormSubmit} />
      </DialogContent>
      <DialogActions>
        <Button onClick={handleCancel}>Cancel</Button>
        <Button
          type="submit"
          form="secure-note-form"
          variant="contained">
          OK
        </Button>
      </DialogActions>
    </Dialog>
  );
}
