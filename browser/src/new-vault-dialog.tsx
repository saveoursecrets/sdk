import * as React from "react";
import Button from "@mui/material/Button";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogContentText from "@mui/material/DialogContentText";
import DialogTitle from "@mui/material/DialogTitle";

import CreateVaultForm from "./create-vault-form";
import { VaultWorker } from "./worker";
import { WorkerContext } from "./worker-provider";

import { NewVaultForm } from "./types";

interface NewVaultProps {
  open: boolean;
  handleCancel: () => void;
  handleOk: (result: NewVaultForm) => void;
}

export default function NewVaultDialog(props: NewVaultProps) {
  const { open, handleCancel, handleOk } = props;
  const onFormSubmit = (result: NewVaultForm) => handleOk(result);

  return (
    <Dialog open={open} onClose={handleCancel}>
      <DialogTitle>New Vault</DialogTitle>
      <DialogContent>
        <DialogContentText gutterBottom>Create a new vault.</DialogContentText>

        <WorkerContext.Consumer>
          {(worker) => {
            return (
              <CreateVaultForm onFormSubmit={onFormSubmit} worker={worker} />
            );
          }}
        </WorkerContext.Consumer>
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
