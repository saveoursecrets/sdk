import * as React from "react";
import Button from "@mui/material/Button";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";
import DialogTitle from "@mui/material/DialogTitle";

import AccountPasswordForm from "../forms/account-password";

import { SecretInfo } from "../../types";

interface AccountPasswordProps {
  open: boolean;
  handleCancel: () => void;
  handleOk: (result: SecretInfo) => void;
}

export default function AccountPasswordDialog(props: AccountPasswordProps) {
  const { open, handleCancel, handleOk } = props;

  return (
    <Dialog open={open} onClose={handleCancel}>
      <DialogTitle color="text.secondary">Account Password</DialogTitle>
      <DialogContent>
        <AccountPasswordForm onFormSubmit={handleOk} />
      </DialogContent>
      <DialogActions>
        <Button onClick={handleCancel}>Cancel</Button>
        <Button type="submit" form="account-password-form" variant="contained">
          OK
        </Button>
      </DialogActions>
    </Dialog>
  );
}
