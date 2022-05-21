import React, { useState } from "react";
import { useDispatch } from "react-redux";

import {
  Button,
  Stack,
  Typography,
  Alert,
  FormControlLabel,
  Checkbox,
} from "@mui/material";

import { createSignup } from "../store/signup";
import { AppDispatch } from '../store';

import { StepProps } from "./index";

export default function Accept(props: StepProps) {
  const dispatch: AppDispatch = useDispatch();
  const { worker, nextStep } = props;
  const [accepted, setAccepted] = useState(false);

  const startSignup = async () => {
    await dispatch(createSignup(worker));
    nextStep();
  };

  return (
    <>
      <Typography variant="h3" gutterBottom>
        Signup
      </Typography>
      <Stack spacing={4}>
        <Stack>
          <Typography variant="body1">
            Please read this page carefully and be certain you understand your
            responsibilities.
          </Typography>
          <Alert severity="warning">
            Before you begin ensure you are in a private space and your screen
            is not visible by other people.
          </Alert>
        </Stack>
        <Stack>
          <Typography variant="h5" gutterBottom>
            Private Key
          </Typography>
          <Typography variant="body1">
            An account requires a private key which will be used as your
            identity for signing on, your private key will be protected by a
            passphrase which you must remember. If you forget this passphrase or
            lose your private key you will not be able to access your vaults.
          </Typography>
          <Alert severity="warning">
            Back up your private key to multiple storage devices and remember
            the passphrase.
          </Alert>
        </Stack>
        <Stack>
          <Typography variant="h5" gutterBottom>
            Encryption Passphrase
          </Typography>
          <Typography variant="body1">
            You will be assigned a random passphrase that will be used to
            encrypt your secrets, you must remember this passphrase otherwise
            you will not be able to read the secrets in your vaults. You may
            wish to write down the passphrase until it has been memorized, once
            you are certain it has been memorized destroy the paper version.{" "}
          </Typography>
          <Alert severity="warning">You must memorize this passphrase.</Alert>
        </Stack>

        <FormControlLabel
          control={<Checkbox />}
          onChange={() => setAccepted(!accepted)}
          label="I will backup my private key and memorize my passphrases"
        />

        <Button disabled={!accepted} variant="contained" onClick={startSignup}>
          Next: Download private key
        </Button>
      </Stack>
    </>
  );
}
