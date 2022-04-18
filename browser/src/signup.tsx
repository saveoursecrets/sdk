import React, { useState } from "react";
import { useSelector, useDispatch } from "react-redux";

import { WorkerProps } from "./props";
import Diceware from "./diceware";
import { download, encode, decode } from "./utils";

import FileUploadReader, { FileBuffer } from "./file-upload-reader";

import { createSignup, setAddress, signupSelector } from "./store/signup";

import {
  Button,
  Stack,
  Typography,
  Alert,
  TextField,
  FormControlLabel,
  Checkbox,
} from "@mui/material";

enum SignupStep {
  ACCEPT = 1,
  PRIVATE_KEY = 2,
  VERIFY_KEY = 3,
  PASSPHRASE = 4,
  COMPLETE = 5,
}

type StepProps = {
  setStep: (value: number) => void;
} & WorkerProps;

function Passphrase(props: StepProps) {
  const { worker, setStep } = props;
  const { signup, address } = useSelector(signupSelector);

  const onGenerate = async (passphrase: string) => {
    await signup.setEncryptionPassphrase(passphrase);
  };

  return (
    <Stack spacing={4}>
      <Stack>
        <Typography variant="h3">Encryption Passphrase</Typography>
        <Typography variant="subtitle1" gutterBottom color="text.secondary">
          {address}
        </Typography>
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

        <Button
          variant="contained"
          onClick={() => setStep(SignupStep.COMPLETE)}
        >
          Next: Verify encryption passphrase
        </Button>
      </Stack>
    </Stack>
  );
}

function VerifyKey(props: StepProps) {
  const { setStep } = props;
  const { signup, address } = useSelector(signupSelector);
  const [verified, setVerified] = useState(false);
  const [keystore, setKeystore] = useState(null);
  const [passphrase, setPassphrase] = useState("");

  const onPassphraseChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setPassphrase(e.target.value);

  const verifyPassphrase = async () => {
    console.log("verify keystore", keystore);
    console.log("verify passphrase", passphrase);

    try {
      await signup.verifyPrivateKey(passphrase, keystore);
    } catch (e) {
      // TODO: handle verification error
      console.error(e);
    }

    setKeystore(null);
    setPassphrase("");
    setVerified(true);

    console.log("Verification completed!");
  };

  const onFileSelect = (file: File) => {
    console.log("file selected", file.name);
  };

  const onFileChange = (data: FileBuffer) => {
    console.log("Got file change event: ", data);
    // TODO: handle UTF-8 decode error
    const contents = decode(new Uint8Array(data.buffer));

    // TODO: handle JSON parse error
    const keystore = JSON.parse(contents);

    if (keystore.address !== address) {
      throw new Error("keystore address is not correct");
    }

    setKeystore(keystore);

    console.log("verify keystore", keystore);
  };

  const NotVerified = () => {
    return keystore === null ? (
      <FileUploadReader onChange={onFileChange} onSelect={onFileSelect} />
    ) : (
      <>
        <Stack>
          <Typography variant="body1">
            Enter the passphrase for the keystore
          </Typography>
          <Typography variant="body2" color="text.secondary">
            To decrypt and verify your keystore file
          </Typography>
        </Stack>
        <form>
          <Stack spacing={2}>
            <TextField
              type="password"
              label="Passphrase"
              value={passphrase}
              onChange={onPassphraseChange}
            />

            <Button onClick={verifyPassphrase}>Verify</Button>
          </Stack>
        </form>
      </>
    );
  };

  const Verified = () => {
    return (
      <Stack spacing={2}>
        <Alert severity="success">
          The passphrase for your private key has been verified.
        </Alert>

        <Button
          variant="contained"
          onClick={() => setStep(SignupStep.PASSPHRASE)}
        >
          Next: Encryption passphrase
        </Button>
      </Stack>
    );
  };

  return (
    <Stack spacing={4}>
      <Stack>
        <Typography variant="h3">Verify Key</Typography>
        <Typography variant="subtitle1" gutterBottom color="text.secondary">
          {address}
        </Typography>
      </Stack>

      <Stack spacing={4}>{!verified ? <NotVerified /> : <Verified />}</Stack>
    </Stack>
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

        {address === null ? (
          <Button onClick={downloadPrivateKey}>Download private key</Button>
        ) : (
          <Button
            variant="contained"
            onClick={() => setStep(SignupStep.VERIFY_KEY)}
          >
            Next: Verify private key
          </Button>
        )}
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
    case SignupStep.COMPLETE:
      return <p>Congratulations, signup is completed!</p>;
  }
}
