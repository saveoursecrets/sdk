import { createSlice, PayloadAction } from "@reduxjs/toolkit";

import { AlertColor } from "@mui/material";

export type SnackbarInfo = {
  message: string;
  severity: AlertColor;
};

export type SnackbarState = {
  snackbar?: SnackbarInfo;
};

const initialState: SnackbarState = {
  snackbar: null,
};

const snackbarSlice = createSlice({
  name: "snackbar",
  initialState,
  reducers: {
    setSnackbar: (state, { payload }: PayloadAction<SnackbarInfo>) => {
      state.snackbar = payload;
    },
  },
});

export const { setSnackbar } = snackbarSlice.actions;
export const snackbarSelector = (state: { snackbar: SnackbarState }) =>
  state.snackbar;
export default snackbarSlice.reducer;
