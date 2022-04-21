import React, { useState } from "react";
import { useSelector, useDispatch } from "react-redux";
import { useNavigate } from "react-router-dom";

import { Button, Stack, Typography } from "@mui/material";

import { WebSigner } from "sos-wasm";

import { WorkerProps } from "../props";

import { decode } from "../utils";

import FileUploadReader, { FileBuffer } from "../file-upload-reader";

import PasswordForm from "../authenticated/forms/password-form";
import PublicAddress from "../components/public-address";

import { login, logout, accountSelector } from "../store/account";
import { setSnackbar } from "../store/snackbar";
import api from "../store/api";

function UploadKey(props: WorkerProps) {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const { worker } = props;
  const { account } = useSelector(accountSelector);
  const [keystore, setKeystore] = useState(null);

  const verifyPassphrase = async (passphrase: string) => {
    try {
      /* eslint-disable @typescript-eslint/no-explicit-any */
      const signer: WebSigner = await new (worker.WebSigner as any)();
      await signer.loadKeystore(passphrase, keystore);
      const { address } = keystore;
      const account = { address, signer };

      dispatch(
        setSnackbar({
          message: "Keystore passphrase verified",
          severity: "success",
        })
      );

      setKeystore(null);
      dispatch(login(account));
    } catch (e) {
      console.error(e);
      dispatch(
        setSnackbar({
          message: `Keystore verification failed`,
          severity: "error",
        })
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
        setKeystore(keystore);
      } catch (e) {
        console.error(e);
        dispatch(
          setSnackbar({
            message: `Could not parse file as JSON: ${e.message || ""}`,
            severity: "error",
          })
        );
      }
    } catch (e) {
      console.error(e);
      dispatch(
        setSnackbar({
          message: `Could not decode file as UTF-8: ${e.message || ""}`,
          severity: "error",
        })
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
          submitLabel="Verify"
          autoFocus
        />
      </>
    );
  };

  return <KeystoreReader />;
}

function VerifyIdentity() {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const { account } = useSelector(accountSelector);
  const { signer } = account;

  const verifyIdentity = async () => {
    const message = new Uint8Array(32);
    self.crypto.getRandomValues(message);

    console.log("verify identity by signing challenge and response", message);

    const signature = await signer.sign(Array.from(message));

    console.log("verify identity by signing challenge and response", signature);

    const [uuid, challenge] = await api.loginChallenge(signature, message);
    console.log("Got challenge", uuid, challenge);

    const responseSignature = await signer.sign(Array.from(challenge));
    await api.loginResponse(responseSignature, uuid, challenge);

    const verified = { ...account, verified: true };
    await dispatch(login(verified));
    navigate("/");
  };

  const cancel = () => {
    dispatch(logout());
  };

  return (
    <Stack direction="row" spacing={2} alignItems="center">
      <Button variant="outlined" color="error" onClick={cancel}>
        Cancel
      </Button>
      <Button variant="contained" onClick={verifyIdentity}>
        Verify my identity
      </Button>
    </Stack>
  );
}

export default function Login(props: WorkerProps) {
  const { worker } = props;
  const { account } = useSelector(accountSelector);

  const view = account ? (
    <>
      <Stack>
        <Typography variant="body1">
          Sign a message to verify your identity.
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Once you have signed the challenge you can unlock your vaults.
        </Typography>
      </Stack>
      <VerifyIdentity />
    </>
  ) : (
    <>
      <Stack>
        <Typography variant="body1">
          Upload your signing key to verify your identity.
        </Typography>
        <Typography variant="body2" color="text.secondary">
          Your signing key is used to verify you are authorized to make changes
          to an account.
        </Typography>
      </Stack>
      <UploadKey worker={worker} />
    </>
  );

  return (
    <Stack spacing={4}>
      <Stack>
        <Typography variant="h3">Login</Typography>
      </Stack>
      <Stack spacing={4}>{view}</Stack>
    </Stack>
  );
}
