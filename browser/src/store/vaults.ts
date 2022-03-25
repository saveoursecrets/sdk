import { createSlice, createAsyncThunk, PayloadAction } from "@reduxjs/toolkit";
import { NavigateFunction } from 'react-router-dom';
import { VaultWorker, WebVault } from "../worker";
import {NewVaultResult} from '../types';

export interface NewVaultRequest {
  worker: VaultWorker;
  result: NewVaultResult;
  navigate: NavigateFunction;
}

export const createVault = createAsyncThunk(
  "vaults/create",
  async (request: NewVaultRequest) => {
    const {worker, navigate, result} = request;
    const { label, password } = result;
    /* eslint-disable @typescript-eslint/no-explicit-any */
    const vault: WebVault = await new (worker.WebVault as any)();
    await vault.initialize(label, password);
    const uuid = await vault.id();
    navigate(`/vault/${uuid}`);
    return { uuid, vault, label, locked: false };
  }
);

export interface VaultStorage {
  uuid: string;
  vault: WebVault;
  label: string;
  locked: boolean;
}

export interface VaultState {
  vaults: VaultStorage[];
}

const initialState: VaultState = {
  vaults: [],
};

const vaultsSlice = createSlice({
  name: "vaults",
  initialState,
  reducers: {
    updateVault: (state, { payload }: PayloadAction<VaultStorage>) => {
      state.vaults = state.vaults.map((prop) => {
        if (payload.uuid === prop.uuid) {
          return payload;
        } else {
          return prop;
        }
      });
    },
  },
  extraReducers: (builder) => {
    builder.addCase(createVault.fulfilled, (state, action) => {
      state.vaults = [action.payload, ...state.vaults];
    })
  },
});

export const { updateVault } = vaultsSlice.actions;
export const vaultsSelector = (state: { vaults: VaultState }) => state.vaults;
export default vaultsSlice.reducer;
