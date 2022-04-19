import React from "react";
import { useSelector, useDispatch } from "react-redux";

import { Stack, Typography } from "@mui/material";

import PasswordForm from "../authenticated/forms/password-form";
import PublicAddress from '../components/public-address';

import { signupSelector } from "../store/signup";
import { setSnackbar } from "../store/snackbar";
import { StepProps } from "./index";

export default function VerifyEncryption(props: StepProps) {
  const dispatch = useDispatch();
  const { nextStep } = props;
  const { address, vault } = useSelector(signupSelector);

  const verifyPassphrase = async (passphrase: string) => {
    try {
      await vault.unlock(passphrase);
      dispatch(
        setSnackbar({
          message: "Encryption passphrase verified",
          severity: "success",
        })
      );
      nextStep();
    } catch (e) {
      dispatch(
        setSnackbar({
          message: `Encryption verification failed`,
          severity: "error",
        })
      );
    }
  };

  return (
    <Stack spacing={4}>
      <Stack>
        <Typography variant="h3">Verify Encryption</Typography>
        <PublicAddress address={address} abbreviate={true} />
      </Stack>
      <Stack spacing={4}>
        <Stack>
          <Typography variant="body1">
            Your login vault has been prepared
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Verify your password to create the new account
          </Typography>
        </Stack>

        <PasswordForm onFormSubmit={verifyPassphrase} submitLabel="Verify" />
      </Stack>
    </Stack>
  );
}
