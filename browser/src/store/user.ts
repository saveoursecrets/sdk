import { createSlice, PayloadAction } from "@reduxjs/toolkit";
import { User } from "../types";

export interface UserState {
  user?: User;
}

const initialState: UserState = {
  user: {
    token: "mock-logged-in-token",
    address: "0x8a67d6f4aae8165512774d63992623e10494c69f",
  },
};

const userSlice = createSlice({
  name: "user",
  initialState,
  reducers: {
    login: (state, { payload }: PayloadAction<User>) => {
      state.user = payload;
    },
    logout: (state, { payload }: PayloadAction<void>) => {
      state.user = null;
    },
    setAuthToken: (state, { payload }: PayloadAction<string>) => {
      let user = { ...state.user, token: payload };
      state.user = user;
    },
  },
});

export const { setAuthToken, login, logout } = userSlice.actions;
export const userSelector = (state: { user: UserState }) => state.user;
export default userSlice.reducer;
