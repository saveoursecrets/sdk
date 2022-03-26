import { createSlice, createAsyncThunk, PayloadAction } from "@reduxjs/toolkit";
import { NavigateFunction } from "react-router-dom";
import { VaultWorker, WebVault } from "../worker";
import { NewVaultResult, SecureNoteResult } from "../types";

export interface NewVaultRequest {
  worker: VaultWorker;
  result: NewVaultResult;
  navigate: NavigateFunction;
}

export interface SecureNoteRequest {
  worker: VaultWorker;
  result: SecureNoteResult;
  owner: VaultStorage;
}

export const lockAll = createAsyncThunk(
  "vaults/lockAll",
  async (storage: VaultStorage[]) => {
    const stores = [];
    for (const store of storage) {
      const newStore = { ...store, locked: true };
      const { vault } = newStore;
      await vault.lock();
      stores.push(newStore);
    }
    return stores;
  }
);

export const createNewVault = createAsyncThunk(
  "vaults/create",
  async (request: NewVaultRequest) => {
    const { worker, navigate, result } = request;
    const { label, password } = result;
    /* eslint-disable @typescript-eslint/no-explicit-any */
    const vault: WebVault = await new (worker.WebVault as any)();
    await vault.initialize(label, password);
    const uuid = await vault.id();
    navigate(`/vault/${uuid}`);
    return { uuid, vault, label, locked: false };
  }
);

export const createNewSecureNote = createAsyncThunk(
  "vaults/createNewSecureNote",
  async (request: SecureNoteRequest) => {
    const { worker, result, owner } = request;
    const { label, note } = result;
    const {vault} = owner;

    console.log("createNewSecureNote", label, note);
    console.log("owner", owner);

    await vault.createNote(label, note);
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
  current?: VaultStorage;
}

const initialState: VaultState = {
  vaults: [],
  current: null,
};

const vaultsSlice = createSlice({
  name: "vaults",
  initialState,
  reducers: {
    setCurrent: (state, { payload }: PayloadAction<VaultStorage>) => {
      state.current = payload;
    },
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
    builder.addCase(createNewVault.fulfilled, (state, action) => {
      state.vaults = [action.payload, ...state.vaults];
      state.current = action.payload;
    });
    builder.addCase(lockAll.fulfilled, (state, action) => {
      state.vaults = action.payload;
    });
  },
});

export const { updateVault, setCurrent } = vaultsSlice.actions;
export const vaultsSelector = (state: { vaults: VaultState }) => state.vaults;
export default vaultsSlice.reducer;
