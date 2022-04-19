import React, { useState } from "react";
import { useSelector, useDispatch } from "react-redux";

import { WebSigner } from "sos-wasm";

import { WorkerProps } from "../props";
import Diceware from "../diceware";
import { download, encode, decode } from "../utils";

import FileUploadReader, { FileBuffer } from "../file-upload-reader";

import PasswordForm from '../authenticated/forms/password-form';

import { createSignup, setAddress, setSigner, setVault, signupSelector } from "../store/signup";
import { createEmptyVault } from "../store/vaults";
import { setSnackbar } from '../store/snackbar';

import SignupCleanup from './cleanup';

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
  VERIFY_ENCRYPTION = 5,
  COMPLETE = 6,
}

type StepProps = {
  setStep: (value: number) => void;
} & WorkerProps;

function VerifyEncryption(props: StepProps) {
  const dispatch = useDispatch();
  const { setStep } = props;
  const { address, vault } = useSelector(signupSelector);

  const verifyPassphrase = async (passphrase: string) => {
    try {
      await vault.unlock(passphrase);
      dispatch(
        setSnackbar(
          {
            message: "Encryption passphrase verified",
            severity: 'success'
          }
        )
      );
      setStep(SignupStep.COMPLETE);
    } catch (e) {
      dispatch(
        setSnackbar(
          {
            message: `Encryption verification failed`,
            severity: 'error'
          }
        )
      );
    }
  }

  return (
    <Stack spacing={4}>
      <Stack>
        <Typography variant="h3">Verify Encryption</Typography>
        <Typography variant="subtitle1" gutterBottom color="text.secondary">
          {address}
        </Typography>
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

        <PasswordForm
          onFormSubmit={verifyPassphrase}
          submitLabel="Verify" />

      </Stack>
    </Stack>
  );
}

function Passphrase(props: StepProps) {
  const dispatch = useDispatch();
  const { worker, setStep } = props;
  const { signup, address, vault } = useSelector(signupSelector);

  const onGenerate = async (passphrase: string) => {
    await signup.setEncryptionPassphrase(passphrase);
  };

  const createVault = async () => {
    const passphrase = await signup.getEncryptionPassphrase();
    const vault = await createEmptyVault(worker);
    await vault.initialize("Login", "", passphrase);
    await vault.lock();
    dispatch(setVault(vault));
    setStep(SignupStep.VERIFY_ENCRYPTION);
  }

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
          onClick={createVault}>
          Next: Verify encryption passphrase
        </Button>
      </Stack>
    </Stack>
  );
}

function VerifyKey(props: StepProps) {
  const dispatch = useDispatch();
  const { worker, setStep } = props;
  const { signup, address } = useSelector(signupSelector);
  const [keystore, setKeystore] = useState(null);

  const verifyPassphrase = async (passphrase: string) => {
    try {
      const signer: WebSigner = await new (worker.WebSigner as any)();
      await signer.loadKeystore(passphrase, keystore);
      dispatch(setSigner(signer));
      dispatch(
        setSnackbar(
          {
            message: "Keystore passphrase verified",
            severity: 'success'
          }
        )
      );

      setKeystore(null);
      setStep(SignupStep.PASSPHRASE)

    } catch (e) {
      console.error(e);
      dispatch(
        setSnackbar(
          {
            message: `Keystore verification failed`,
            severity: 'error'
          }
        )
      );
    }
  };

  const onFileSelect = (file: File) => {
    console.log("file selected", file.name);
  };

  const onFileChange = (data: FileBuffer) => {
    console.log("Got file change event: ", data);

    try {
      const contents = decode(new Uint8Array(data.buffer));
      try {
        const keystore = JSON.parse(contents);
        if (keystore.address !== address) {
          dispatch(
            setSnackbar(
              {
                message: `Keystore address ${keystore.address} does not match expected address: ${address}, perhaps you uploaded the wrong keystore?`,
                severity: 'error'
              }
            )
          );
        }
        setKeystore(keystore);
      } catch (e) {
        console.error(e);
        dispatch(
          setSnackbar(
            {
              message: `Could not parse file as JSON: ${e.message || ''}`,
              severity: 'error'
            }
          )
        );
      }
    } catch (e) {
      console.error(e);
      dispatch(
        setSnackbar(
          {
            message: `Could not decode file as UTF-8: ${e.message || ''}`,
            severity: 'error'
          }
        )
      );
    }
  };

  const KeystoreReader = () => {
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

        <PasswordForm
          onFormSubmit={verifyPassphrase}
          submitLabel="Verify" />

      </>
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

      <Stack spacing={4}>
        <KeystoreReader />
      </Stack>
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
        <Stack>
          <Typography variant="body1">
            Please read this page carefully and be certain you understand your
            responsibilities.
          </Typography>
          <Alert severity="warning">
            Before you begin ensure you are in a private space and your screen is not visible by other people.
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

function SignupStepView(props: WorkerProps) {
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
    case SignupStep.VERIFY_ENCRYPTION:
      return <VerifyEncryption worker={worker} setStep={setStep} />;
    case SignupStep.COMPLETE:
      return <p>Congratulations, signup is completed! TODO: send vault to create new account on remote server</p>;
  }
}

export default function SignupView(props: WorkerProps) {
  const { worker } = props;
  return (
    <>
      <SignupStepView worker={worker} />
      <SignupCleanup />
    </>
  );
}
