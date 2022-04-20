import React from "react";
import { useSelector, useDispatch } from "react-redux";

import { Button, Stack, Typography, Alert } from "@mui/material";

import Diceware from "../diceware";

import { setVault, signupSelector } from "../store/signup";
import { createEmptyVault } from "../store/vaults";
import PublicAddress from "../components/public-address";

import { StepProps } from "./index";

export default function EncryptionPassphrase(props: StepProps) {
  const dispatch = useDispatch();
  const { worker, nextStep } = props;
  const { signup, address } = useSelector(signupSelector);

  const onGenerate = async (passphrase: string) => {
    await signup.setEncryptionPassphrase(passphrase);
  };

  const createVault = async () => {
    const passphrase = await signup.getEncryptionPassphrase();
    const vault = await createEmptyVault(worker);
    await vault.initialize("Login", "", passphrase);
    await vault.lock();
    dispatch(setVault(vault));
    nextStep();
  };

  return (
    <Stack spacing={4}>
      <Stack>
        <Typography variant="h3">Encryption Passphrase</Typography>
        <PublicAddress address={address} abbreviate={true} />
      </Stack>
      <Stack spacing={4}>
        <Stack>
          <Typography variant="body1">
            Choose a passphrase used to encrypt your secrets.
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Use the refresh button to select another passphrase at random.
          </Typography>
        </Stack>

        <Diceware onGenerate={onGenerate} worker={worker} />

        <Alert severity="warning">You must memorize this passphrase.</Alert>

        <Button variant="contained" onClick={createVault}>
          Next: Verify encryption passphrase
        </Button>
      </Stack>
    </Stack>
  );
}
