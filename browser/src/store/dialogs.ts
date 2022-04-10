import { createSlice, PayloadAction } from "@reduxjs/toolkit";

export const NEW_VAULT = "new-vault";
export const NEW_SECURE_NOTE = "new-secure-note";
export const NEW_ACCOUNT_PASSWORD = "new-account-password";
export const NEW_CREDENTIALS = "new-credentials";
export const NEW_FILE_UPLOAD = "new-file-upload";
export const CONFIRM_DELETE_SECRET = "confirm-delete-secret";

const dialogs: DialogDict = {};
dialogs[NEW_VAULT] = [false, null];
dialogs[NEW_SECURE_NOTE] = [false, null];
dialogs[NEW_ACCOUNT_PASSWORD] = [false, null];
dialogs[NEW_CREDENTIALS] = [false, null];
dialogs[NEW_FILE_UPLOAD] = [false, null];
dialogs[CONFIRM_DELETE_SECRET] = [false, null];

export interface DialogDict {
  [index: string]: [boolean, unknown?];
}

export interface DialogState {
  dialogs: DialogDict;
}

const initialState: DialogState = { dialogs };

const dialogsSlice = createSlice({
  name: "dialogs",
  initialState,
  reducers: {
    setDialogVisible: (
      state,
      { payload }: PayloadAction<[string, boolean, unknown]>
    ) => {
      const [key, value, data] = payload;
      const dialogs = Object.assign(state.dialogs);
      dialogs[key] = [value, data];
      state.dialogs = dialogs;
    },
  },
});

export const { setDialogVisible } = dialogsSlice.actions;
export const dialogsSelector = (state: { dialogs: DialogState }) =>
  state.dialogs;
export default dialogsSlice.reducer;
