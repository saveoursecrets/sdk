import * as React from "react";
import Alert from "@mui/material/Alert";
import Stack from "@mui/material/Stack";
import Box from "@mui/material/Box";
import Paper from "@mui/material/Paper";
import Button from "@mui/material/Button";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogTitle from "@mui/material/DialogTitle";
import Typography from "@mui/material/Typography";

import { SecretReference } from "../../types";
import ConfirmValueForm from "../forms/confirm-value";

interface ConfirmDeleteSecretProps {
  open: boolean;
  secret?: SecretReference;
  handleCancel: () => void;
  handleOk: () => void;
}

export default function ConfirmDeleteSecretDialog(
  props: ConfirmDeleteSecretProps
) {
  const { open, secret, handleCancel, handleOk } = props;

  if (!secret) {
    return null;
  }

  return (
    <Dialog open={open} onClose={handleCancel}>
      <DialogTitle color="text.secondary">Delete Secret</DialogTitle>
      <DialogContent>
        <Stack spacing={2}>
          <Typography variant="body1" component="div">
            Are you sure you want to permanently delete this secret?
          </Typography>

          <Paper variant="outlined">
            <Box padding={2}>{secret.label}</Box>
          </Paper>

          <Typography variant="body1" component="div">
            Type the secret name to confirm:
          </Typography>

          <ConfirmValueForm
            value={secret.label}
            onFormSubmit={() => console.log("got correct value")}
          />

          <Alert severity="warning">
            Deletion is permanent, it cannot be undone.
          </Alert>
        </Stack>
      </DialogContent>
      <DialogActions>
        <Button onClick={handleCancel}>Cancel</Button>
        <Button type="submit" form="delete-secret-form" variant="contained">
          OK
        </Button>
      </DialogActions>
    </Dialog>
  );
}
