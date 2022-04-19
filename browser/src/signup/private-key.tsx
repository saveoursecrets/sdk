import React from "react";
import { useSelector, useDispatch } from "react-redux";

import { Button, Stack, Typography } from "@mui/material";

import Diceware from "../diceware";
import { download, encode } from "../utils";

import { setAddress, signupSelector } from "../store/signup";

import { StepProps } from "./index";

export default function PrivateKey(props: StepProps) {
  const dispatch = useDispatch();
  const { signup, address } = useSelector(signupSelector);
  const { worker, nextStep } = props;

  const onGenerate = async (passphrase: string) => {
    await signup.setPassphrase(passphrase);
  };

  const downloadPrivateKey = async () => {
    const keystore = await signup.generatePrivateKey();
    const { address } = keystore;
    dispatch(setAddress(address));
    const fileName = `${address}.json`;
    const contents = encode(JSON.stringify(keystore, undefined, 2));
    download(fileName, contents);
  };

  return (
    <>
      <Typography variant="h3" gutterBottom>
        Private Key
      </Typography>
      <Stack spacing={4}>
        <Stack>
          <Typography variant="body1">
            Choose a passphrase to protect your private key.
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Use the refresh button to select another passphrase at random.
          </Typography>
        </Stack>

        <Diceware onGenerate={onGenerate} worker={worker} />

        <Stack>
          <Typography variant="body1">
            Once you have decided on a passphrase click the download button to
            save your private key.
          </Typography>
          <Typography variant="body2" color="text.secondary">
            You will need to upload your private key on the next screen for
            verification.
          </Typography>
        </Stack>

        {address === null ? (
          <Button onClick={downloadPrivateKey}>Download private key</Button>
        ) : (
          <Button variant="contained" onClick={() => nextStep()}>
            Next: Verify private key
          </Button>
        )}
      </Stack>
    </>
  );
}
