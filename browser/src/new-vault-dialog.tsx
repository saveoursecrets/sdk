import * as React from "react";
import Alert from "@mui/material/Alert";
import Button from "@mui/material/Button";
import Checkbox from "@mui/material/Checkbox";
import FormControlLabel from "@mui/material/FormControlLabel";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogTitle from "@mui/material/DialogTitle";

import CreateVaultForm from "./create-vault-form";

import { NewVaultResult } from "./types";

interface NewVaultProps {
  open: boolean;
  handleCancel: () => void;
  handleOk: (result: NewVaultResult) => void;
}

export default function NewVaultDialog(props: NewVaultProps) {
  const { open, handleCancel, handleOk } = props;
  const onFormSubmit = (result: NewVaultResult) => handleOk(result);

  return (
    <Dialog open={open} onClose={handleCancel} fullScreen>
      <DialogTitle>New Vault</DialogTitle>
      <DialogContent>
        <CreateVaultForm onFormSubmit={onFormSubmit} />
        <Alert sx={{ marginTop: 2 }} severity="warning">
          You must memorize or write down the passphrase for your new vault
        </Alert>
        <FormControlLabel
          control={<Checkbox />}
          label="I have memorized or written down the passphrase"
        />
      </DialogContent>
      <DialogActions>
        <Button onClick={handleCancel}>Cancel</Button>
        <Button type="submit" form="new-vault-form" variant="contained">
          OK
        </Button>
      </DialogActions>
    </Dialog>
  );
}
