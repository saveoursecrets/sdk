import React, { useState } from "react";
import { useDispatch } from "react-redux";

import { Stack, Typography } from "@mui/material";

import { WebSigner } from "sos-wasm";

import { WorkerProps } from "../props";

import { decode } from "../utils";

import FileUploadReader, { FileBuffer } from "../components/file-upload-reader";
import PasswordForm from "../authenticated/forms/password-form";

import { login } from "../store/account";
import { setSnackbar } from "../store/snackbar";

export default function UploadKey(props: WorkerProps) {
  const dispatch = useDispatch();
  const { worker } = props;
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
