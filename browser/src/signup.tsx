import React, { useState } from "react";

import {
  Button,
  Stack,
  Typography,
  Alert,
  FormControlLabel,
  Checkbox,
} from "@mui/material";

export default function Signup() {
  const [accepted, setAccepted] = useState(false);

  return (
    <>
      <Typography variant="h3" gutterBottom>
        Signup
      </Typography>
      <Stack spacing={2}>
        <Typography variant="body1">
          Please read this page carefully and be sure you understand your
          responsibilities.
        </Typography>

        <Typography variant="h5" gutterBottom>
          Private Key
        </Typography>
        <Typography variant="body1">
          An account requires a private key which will be used as your identity
          for signing on, your private key will be protected by a passphrase
          which you must remember. If you forget this passphrase or lose your
          private key you will not be able to access your vaults.
        </Typography>
        <Alert severity="warning">
          Remember to back up your private key to multiple storage devices and
          remember the passphrase.
        </Alert>
        <Typography variant="h5" gutterBottom>
          Encryption Passphrase
        </Typography>
        <Typography variant="body1">
          You will be assigned a random passphrase that will be used to encrypt
          your secrets, you must remember this passphrase otherwise you will not
          be able to read the secrets in your vaults. You may wish to write down
          the passphrase until it has been memorized, once you are certain it
          has been memorized destroy the paper version. To help you remember the
          passphrase we will ask you to type it several times when creating a
          new account.
        </Typography>
        <Alert severity="warning">You must memorize this passphrase.</Alert>

        <FormControlLabel
          control={<Checkbox />}
          onChange={() => setAccepted(!accepted)}
          label="I will backup my private key and memorize my passphrases"
        />

        <Button disabled={!accepted} variant="contained">
          Create new account
        </Button>
      </Stack>
    </>
  );
}
