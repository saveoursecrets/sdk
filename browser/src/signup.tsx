import React, { useState } from "react";
import { useSelector, useDispatch } from "react-redux";

import { WorkerProps } from "./props";
import Diceware from "./diceware";
import { download, encode, decode } from "./utils";

import FileUploadReader, { FileBuffer } from './file-upload-reader';

import { createSignup, setAddress, signupSelector } from "./store/signup";

import {
  Button,
  Stack,
  Typography,
  Alert,
  FormControlLabel,
  Checkbox,
} from "@mui/material";

enum SignupStep {
  ACCEPT = 1,
  PRIVATE_KEY = 2,
  VERIFY_KEY = 3,
  PASSPHRASE = 4,
}

type StepProps = {
  setStep: (value: number) => void;
} & WorkerProps;

function Passphrase(props: StepProps) {
  const { setStep } = props;
  return (
    <>
      <Typography variant="h3" gutterBottom>
        Encryption Passphrase
      </Typography>
      <Stack spacing={4}></Stack>
    </>
  );
}

function VerifyKey(props: StepProps) {
  const { signup, address } = useSelector(signupSelector);

  const onFileChange = (data: FileBuffer) => {
    console.log("Got file change event: ", data);
    // TODO: handle UTF-8 decode error
    const contents = decode(data.buffer);

    // TODO: handle JSON parse error
    const keystore = JSON.parse(contents);

    if (keystore.address !== address) {
      throw new Error("keystore address is not valid");
    }

    console.log("verify keystore", keystore);
  }

  return (
    <>
      <Typography variant="h3" gutterBottom>
        Verify Key
      </Typography>
      <Stack spacing={4}>
        <Typography
          variant="subtitle1" gutterBottom>
          {address}
        </Typography>

        <FileUploadReader onChange={onFileChange} />
      </Stack>
    </>
  );
}

function PrivateKey(props: StepProps) {
  const dispatch = useDispatch();
  const { signup, address } = useSelector(signupSelector);
  const { worker, setStep } = props;

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

        {
          address === null ?
            (
              <Button
                onClick={downloadPrivateKey}
              >
                Download private key
              </Button>
            ) :
            (
              <Button
                variant="contained"
                onClick={() => setStep(SignupStep.VERIFY_KEY)}
              >
                Next: Verify private key
              </Button>
            )
        }

      </Stack>
    </>
  );
}

function Accept(props: StepProps) {
  const dispatch = useDispatch();
  const { worker, setStep } = props;
  const [accepted, setAccepted] = useState(false);

  const startSignup = async () => {
    await dispatch(createSignup(worker));
    setStep(SignupStep.PRIVATE_KEY);
  };

  return (
    <>
      <Typography variant="h3" gutterBottom>
        Signup
      </Typography>
      <Stack spacing={4}>
        <Typography variant="body1">
          Please read this page carefully and be sure you understand your
          responsibilities.
        </Typography>
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
            you are certain it has been memorized destroy the paper version. To
            help you remember the passphrase we will ask you to type it several
            times when creating a new account.
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

export default function SignupView(props: WorkerProps) {
  const { worker } = props;
  const [step, setStep] = useState(SignupStep.ACCEPT);

  switch (step) {
    case SignupStep.ACCEPT:
      return <Accept worker={worker} setStep={setStep} />;
    case SignupStep.PRIVATE_KEY:
      return <PrivateKey worker={worker} setStep={setStep} />;
    case SignupStep.VERIFY_KEY:
      return <VerifyKey worker={worker} setStep={setStep} />;
    case SignupStep.PASSPHRASE:
      return <Passphrase worker={worker} setStep={setStep} />;
  }
}
