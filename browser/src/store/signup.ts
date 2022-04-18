import {
  createSlice,
  createAsyncThunk,
  PayloadAction,
  isRejected,
} from "@reduxjs/toolkit";
import { Signup } from "sos-wasm";
import { VaultWorker } from "../types";

const logError = (state: SignupState, action: PayloadAction<Error>) => {
  //const { payload } = action;
  console.error(action.payload);
};

export const createSignup = createAsyncThunk(
  "signup/new",
  async (worker: VaultWorker) => {
    /* eslint-disable @typescript-eslint/no-explicit-any */
    const signup: Signup = await new (worker.Signup as any)();
    return signup;
  }
);

export const deleteSignup = createAsyncThunk(
  "signup/delete",
  async (signup: Signup) => {
    await signup.dispose();
  }
);

type SignupState = {
  signup?: Signup;
  address?: string;
};

const initialState: SignupState = {
  signup: null,
  address: null,
};

const signupSlice = createSlice({
  name: "signup",
  initialState,
  reducers: {
    setAddress: (state, { payload }: PayloadAction<string>) => {
      state.address = payload;
    },
  },
  extraReducers: (builder) => {
    builder.addCase(createSignup.fulfilled, (state, action) => {
      state.signup = action.payload;
    });
    builder.addCase(deleteSignup.fulfilled, (state) => {
      state.signup = null;
      state.address = null;
    });
    builder.addMatcher(isRejected, logError);
  },
});

export const { setAddress } = signupSlice.actions;
export const signupSelector = (state: { signup: SignupState }) => state.signup;
export default signupSlice.reducer;
