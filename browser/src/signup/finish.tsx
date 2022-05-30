import React from "react";
import { useSelector, useDispatch } from "react-redux";
import { useNavigate } from "react-router-dom";

import { Button, Stack, Typography } from "@mui/material";

import { signupSelector } from "../store/signup";
import { login } from "../store/account";
import { setSnackbar } from "../store/snackbar";
import api from "../store/api";
import PublicAddress from "../components/public-address";

//import { StepProps } from "./index";

export default function Finish(/*props: StepProps*/) {
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const { signer, vault, address } = useSelector(signupSelector);
  //const { worker } = props;

  const saveVault = async () => {
    const buffer = await vault.buffer();
    const signature = await signer.sign(Array.from(buffer));
    await api.createAccount(signature, buffer);
    const account = { address, signer };
    await dispatch(login(account));
    dispatch(setSnackbar({ message: "Account created", severity: "success" }));
    navigate("/login");
  };

  return (
    <Stack spacing={4}>
      <Stack>
        <Typography variant="h3">Save Vault</Typography>
        <PublicAddress address={address} abbreviate={true} />
      </Stack>
      <Stack spacing={4}>
        <Stack>
          <Typography variant="body1">
            Well done, just one more step to complete the signup.
          </Typography>
          <Typography variant="body2" color="text.secondary">
            Send your login vault to be saved so you can share it across
            different devices.
          </Typography>
        </Stack>
        <Button variant="contained" onClick={saveVault}>
          Save Vault
        </Button>
      </Stack>
    </Stack>
  );
}
