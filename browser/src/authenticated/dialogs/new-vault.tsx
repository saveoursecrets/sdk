import * as React from "react";
import Alert from "@mui/material/Alert";
import Button from "@mui/material/Button";
import Checkbox from "@mui/material/Checkbox";
import FormControlLabel from "@mui/material/FormControlLabel";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogTitle from "@mui/material/DialogTitle";

import CreateVaultForm from "../forms/create-vault";

import { NewVaultResult } from "../../types";

interface NewVaultProps {
  open: boolean;
  handleCancel: () => void;
  handleOk: (result: NewVaultResult) => void;
}

export default function NewVaultDialog(props: NewVaultProps) {
  const { open, handleCancel, handleOk } = props;

  return (
    <Dialog open={open} onClose={handleCancel}>
      <DialogTitle color="text.secondary">
        New Vault
      </DialogTitle>
      <DialogContent>
        <CreateVaultForm onFormSubmit={handleOk} />
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
