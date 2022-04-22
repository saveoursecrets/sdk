import React from "react";
import { useSelector, useDispatch } from "react-redux";
import { useNavigate } from 'react-router-dom';

import { Button, Stack } from "@mui/material";

import { login, logout, accountSelector } from "../store/account";
import api from "../store/api";

export default function VerifyIdentity() {
  const dispatch = useDispatch();
  const navigate = useNavigate();
  const { account } = useSelector(accountSelector);
  const { signer } = account;

  const verifyIdentity = async () => {
    const message = new Uint8Array(32);
    self.crypto.getRandomValues(message);
    const signature = await signer.sign(Array.from(message));
    const [uuid, challenge] = await api.loginChallenge(signature, message);
    const responseSignature = await signer.sign(Array.from(challenge));
    const summaries = await api.loginResponse(responseSignature, uuid, challenge);
    const verified = { ...account, summaries };
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
