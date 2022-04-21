import { createSlice, PayloadAction } from "@reduxjs/toolkit";
import { Account } from "../types";

export interface AccountState {
  account?: Account;
}

const initialState: AccountState = {
  account: null,
};

const accountSlice = createSlice({
  name: "account",
  initialState,
  reducers: {
    login: (state, { payload }: PayloadAction<Account>) => {
      state.account = payload;
    },
    logout: (state) => {
      state.account = null;
    },
  },
});

export const { login, logout } = accountSlice.actions;
export const accountSelector = (state: { account: AccountState }) =>
  state.account;
export default accountSlice.reducer;
