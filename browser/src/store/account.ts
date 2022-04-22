import { createSlice, PayloadAction } from "@reduxjs/toolkit";
import { Account } from "../types";

export interface AccountState {
  account?: Account;
  selectedIndex: number;
}

const initialState: AccountState = {
  account: null,
  selectedIndex: -1,
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
    setSelectedIndex: (state, { payload }: PayloadAction<number>) => {
      state.selectedIndex = payload;
    },
  },
});

export const { login, logout, setSelectedIndex } = accountSlice.actions;
export const accountSelector = (state: { account: AccountState }) =>
  state.account;
export default accountSlice.reducer;
