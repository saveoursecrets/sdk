import React from "react";
import { useSelector } from "react-redux";

import { Stack, Typography } from "@mui/material";

import { WorkerProps } from "../props";
import { accountSelector } from "../store/account";

import UploadKey from "./upload-key";
import VerifyIdentity from "./verify-identity";

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
    <Stack padding={3} spacing={4}>
      <Stack>
        <Typography variant="h3">Login</Typography>
      </Stack>
      <Stack spacing={4}>{view}</Stack>
    </Stack>
  );
}
