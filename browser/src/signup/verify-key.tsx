import React, { useState } from "react";
import { useSelector, useDispatch } from "react-redux";

import { Stack, Typography } from "@mui/material";

import { WebSigner } from "sos-wasm";

import { decode } from "../utils";

import FileUploadReader, { FileBuffer } from "../components/file-upload-reader";

import PasswordForm from "../authenticated/forms/password-form";
import PublicAddress from "../components/public-address";

import { setSigner, signupSelector } from "../store/signup";
import { setSnackbar } from "../store/snackbar";

import { StepProps } from "./index";

export default function VerifyKey(props: StepProps) {
  const dispatch = useDispatch();
  const { worker, nextStep } = props;
  const { address } = useSelector(signupSelector);
  const [keystore, setKeystore] = useState(null);

  const verifyPassphrase = async (passphrase: string) => {
    try {
      /* eslint-disable @typescript-eslint/no-explicit-any */
      const signer: WebSigner = await new (worker.WebSigner as any)();
      await signer.loadKeystore(passphrase, keystore);
      dispatch(setSigner(signer));
      dispatch(
        setSnackbar({
          message: "Keystore passphrase verified",
          severity: "success",
        })
      );

      setKeystore(null);
      nextStep();
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
        if (keystore.address !== address) {
          dispatch(
            setSnackbar({
              message: `Keystore address ${keystore.address} does not match expected address: ${address}, perhaps you uploaded the wrong keystore?`,
              severity: "error",
            })
          );
        }
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

        <PasswordForm onFormSubmit={verifyPassphrase} submitLabel="Verify" />
      </>
    );
  };

  return (
    <Stack spacing={4}>
      <Stack>
        <Typography variant="h3">Verify Key</Typography>
        <PublicAddress address={address} abbreviate={true} />
      </Stack>

      <Stack spacing={4}>
        <KeystoreReader />
      </Stack>
    </Stack>
  );
}
