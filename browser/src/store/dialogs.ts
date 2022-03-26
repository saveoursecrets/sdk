import { createSlice, PayloadAction } from "@reduxjs/toolkit";

export const NEW_VAULT = "new-vault";
export const NEW_SECURE_NOTE = "new-secure-note";
export const NEW_ACCOUNT_PASSWORD = "new-account-password";

export interface DialogDict {
  [index: string]: boolean;
}

export interface DialogState {
  dialogs: DialogDict;
}

const initialState: DialogState = {
  dialogs: {},
};

const dialogsSlice = createSlice({
  name: "dialogs",
  initialState,
  reducers: {
    setDialogVisible: (
      state,
      { payload }: PayloadAction<[string, boolean]>
    ) => {
      const [key, value] = payload;
      const dialogs = Object.assign(state.dialogs);
      dialogs[key] = value;
      state.dialogs = dialogs;
    },
  },
});

export const { setDialogVisible } = dialogsSlice.actions;
export const dialogsSelector = (state: { dialogs: DialogState }) =>
  state.dialogs;
export default dialogsSlice.reducer;
