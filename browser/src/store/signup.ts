import {
  createSlice,
  createAsyncThunk,
  PayloadAction,
  isRejected,
  AnyAction,
} from "@reduxjs/toolkit";
import { WebVault, WebSigner, Signup } from "sos-wasm";
import { VaultWorker } from "../types";

const logError = (state: SignupState, action: AnyAction) => {
  console.error("", action.payload);
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
  async (signup?: Signup) => {
    if (signup) {
      await signup.dispose();
    }
  }
);

export type SignupState = {
  signup?: Signup;
  address?: string;
  signer?: WebSigner;
  vault?: WebVault;
};

const initialState: SignupState = {
  signup: null,
  address: null,
  signer: null,
  vault: null,
};

const signupSlice = createSlice({
  name: "signup",
  initialState,
  reducers: {
    setAddress: (state, { payload }: PayloadAction<string>) => {
      state.address = payload;
    },
    setSigner: (state, { payload }: PayloadAction<WebSigner>) => {
      state.signer = payload;
    },
    setVault: (state, { payload }: PayloadAction<WebVault>) => {
      state.vault = payload;
    },
  },
  extraReducers: (builder) => {
    builder.addCase(createSignup.fulfilled, (state, action) => {
      state.signup = action.payload;
    });
    builder.addCase(deleteSignup.fulfilled, (state) => {
      state.signup = null;
      state.address = null;
      state.signer = null;
      state.vault = null;
    });
    builder.addMatcher(isRejected, logError);
  },
});

export const { setAddress, setSigner, setVault } = signupSlice.actions;
export const signupSelector = (state: { signup: SignupState }) => state.signup;
export default signupSlice.reducer;
