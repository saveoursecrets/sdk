import * as React from "react";
import Button from "@mui/material/Button";
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

  return (
    <Dialog open={open} onClose={handleCancel}>
      <DialogTitle color="text.secondary">Secure Note</DialogTitle>
      <DialogContent>
        <SecureNoteForm label="" note="" onFormSubmit={handleOk} />
      </DialogContent>
      <DialogActions>
        <Button onClick={handleCancel}>Cancel</Button>
        <Button type="submit" form="secure-note-form" variant="contained">
          OK
        </Button>
      </DialogActions>
    </Dialog>
  );
}
