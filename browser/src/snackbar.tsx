import React, { useState } from "react";
import { useDispatch, useSelector } from 'react-redux';

import {
  Snackbar,
  Alert,
} from "@mui/material";

import { snackbarSelector, setSnackbar } from './store/snackbar';

export default function SnackbarHandler() {
  const dispatch = useDispatch();
  const { snackbar } = useSelector(snackbarSelector);
  const open = snackbar !== null;

  if (!snackbar) {
    return null;
  }

  const closeSnackbar = (
    event?: React.SyntheticEvent | Event,
    reason?: string
  ) => {
    if (reason === "clickaway") {
      return;
    }
    dispatch(setSnackbar(null));
  };

  return (
    <Snackbar open={open} autoHideDuration={4000} onClose={closeSnackbar}>
      <Alert onClose={closeSnackbar} severity={snackbar.severity}>
        {snackbar.message}
      </Alert>
    </Snackbar>
  );
}
