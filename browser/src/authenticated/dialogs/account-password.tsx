import * as React from "react";
import Button from "@mui/material/Button";
import Dialog from "@mui/material/Dialog";
import DialogActions from "@mui/material/DialogActions";
import DialogContent from "@mui/material/DialogContent";

import AccountPasswordForm from "../forms/account-password";

import { AccountPasswordResult } from "../../types";

interface AccountPasswordProps {
  open: boolean;
  handleCancel: () => void;
  handleOk: (result: AccountPasswordResult) => void;
}

export default function AccountPasswordDialog(props: AccountPasswordProps) {
  const { open, handleCancel, handleOk } = props;

  return (
    <Dialog open={open} onClose={handleCancel}>
      <DialogContent>
        <AccountPasswordForm
          label=""
          account=""
          url=""
          password=""
          onFormSubmit={handleOk} />
      </DialogContent>
      <DialogActions>
        <Button onClick={handleCancel}>Cancel</Button>
        <Button
          type="submit"
          form="account-password-form"
          variant="contained">
          OK
        </Button>
      </DialogActions>
    </Dialog>
  );
}
