import { createSlice, createAsyncThunk, PayloadAction } from "@reduxjs/toolkit";
import { NavigateFunction } from "react-router-dom";
import { WebVault } from "sos-wasm";

import api from './api';
import {
  NewVaultResult,
  SecureNoteResult,
  AccountPasswordResult,
  CredentialsResult,
  FileUploadResult,
  SearchMeta,
  User,
  VaultWorker,
} from "../types";

export interface VaultSearchIndex {
  [index: string]: SearchMeta;
}

export interface VaultStorage {
  uuid: string;
  vault: WebVault;
  label: string;
  locked: boolean;
  index?: VaultSearchIndex;
}

export interface VaultState {
  vaults: VaultStorage[];
  current?: VaultStorage;
}

export interface NewVaultRequest {
  worker: VaultWorker;
  result: NewVaultResult;
  navigate: NavigateFunction;
}

export interface AccountPasswordRequest {
  result: AccountPasswordResult;
  owner: VaultStorage;
}

export interface SecureNoteRequest {
  result: SecureNoteResult;
  owner: VaultStorage;
}

export interface CredentialsRequest {
  result: CredentialsResult;
  owner: VaultStorage;
}

export interface FileUploadRequest {
  result: FileUploadResult;
  owner: VaultStorage;
}

interface LoadVaultsRequest {
  user: User,
  worker: VaultWorker,
}

export const loadVaults = createAsyncThunk(
  "vaults/loadVaults",
  async (request: LoadVaultsRequest) => {
    const {user, worker} = request;
    const ids = await api.loadVaults(user);

    console.log(ids);

    const buffers = ids.map(async (id) => {
      return await api.getVault(user, id);
    });

    const vaults = await Promise.all(buffers);
    const dict: any = {};
    for (const [index, id] of ids.entries()) {
      dict[id] = vaults[index];
    }

    console.log(dict);

    const storage = Object.entries(dict).map(async (item: [string, ArrayBuffer]) => {
      const [id, buffer] = item;

      console.log("worker", worker);

      const vault: WebVault = await new (worker.WebVault as any)();

      console.log("vault", vault);

      try {
        console.log("Calling import buffer...");
        await vault.importBuffer(new Uint8Array(buffer));

        console.log("AFTER IMPORT BUFFER");

      } catch(e) {
        console.error(e);
      }

      return {
        uuid: id,
        label: id,
        vault,
        locked: true,
      }
    });

    return await Promise.all(storage);
  }
);

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
    const index = await vault.getSecretIndex();
    navigate(`/vault/${uuid}`);
    return { uuid, vault, label, locked: false, index };
  }
);

export const createNewAccountPassword = createAsyncThunk(
  "vaults/createNewAccountPassword",
  async (request: AccountPasswordRequest) => {
    const { result, owner } = request;
    const { vault } = owner;
    await vault.createAccountPassword(result);
    const index = await vault.getSecretIndex();
    return { ...owner, index };
  }
);

export const createNewSecureNote = createAsyncThunk(
  "vaults/createNewSecureNote",
  async (request: SecureNoteRequest) => {
    const { result, owner } = request;
    const { vault } = owner;
    await vault.createNote(result);
    const index = await vault.getSecretIndex();
    return { ...owner, index };
  }
);

export const createNewCredentials = createAsyncThunk(
  "vaults/createNewCredentials",
  async (request: CredentialsRequest) => {
    const { result, owner } = request;
    const { vault } = owner;
    await vault.createCredentials(result);
    const index = await vault.getSecretIndex();
    return { ...owner, index };
  }
);

export const createNewFileUpload = createAsyncThunk(
  "vaults/createNewFileUpload",
  async (request: FileUploadRequest) => {
    const { result, owner } = request;
    const { vault } = owner;
    try {
      await vault.createFileUpload(result);
    } catch(e) {
      console.error(e);
    }
    const index = await vault.getSecretIndex();
    return { ...owner, index };
  }
);

const initialState: VaultState = {
  vaults: [],
  current: null,
};

const updateVaultFromThunk = (
  state: VaultState,
  action: PayloadAction<VaultStorage>
) => {
  const { payload } = action;
  state.current = payload;
  state.vaults = state.vaults.map((prop: VaultStorage) => {
    if (payload.uuid === prop.uuid) {
      return payload;
    } else {
      return prop;
    }
  });
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
    builder.addCase(loadVaults.fulfilled, (state, action) => {
      state.vaults = action.payload;
    });
    builder.addCase(lockAll.fulfilled, (state, action) => {
      state.vaults = action.payload;
    });
    builder.addCase(createNewAccountPassword.fulfilled, updateVaultFromThunk);
    builder.addCase(createNewSecureNote.fulfilled, updateVaultFromThunk);
    builder.addCase(createNewCredentials.fulfilled, updateVaultFromThunk);
    builder.addCase(createNewFileUpload.fulfilled, updateVaultFromThunk);
  },
});

export const { updateVault, setCurrent } = vaultsSlice.actions;
export const vaultsSelector = (state: { vaults: VaultState }) => state.vaults;
export default vaultsSlice.reducer;
