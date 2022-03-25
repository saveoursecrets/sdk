import { createSlice, PayloadAction } from "@reduxjs/toolkit";

export interface UserState {
  token?: string;
}

const initialState: UserState = {
  token: "mock-logged-in-token",
};

const userSlice = createSlice({
  name: "user",
  initialState,
  reducers: {
    setAuthToken: (state, { payload }: PayloadAction<string>) => {
      state.token = payload;
    },
  },
});

export const { setAuthToken } = userSlice.actions;
export const userSelector = (state: { user: UserState }) => state.user;
export default userSlice.reducer;
