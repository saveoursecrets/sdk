import { createSlice, createAsyncThunk, PayloadAction } from "@reduxjs/toolkit";
import { NavigateFunction } from "react-router-dom";
import { WebVault } from "sos-wasm";

import api from "./api";
import {
  NewVaultResult,
  SecretMeta,
  SecretInfo,
  User,
  VaultWorker,
} from "../types";

export type VaultMetaData = {
  [index: string]: [string, SecretMeta];
};

export type VaultStorage = {
  uuid: string;
  vault: WebVault;
  label: string;
  locked: boolean;
  meta?: VaultMetaData;
};

export type VaultState = {
  vaults: VaultStorage[];
  current?: VaultStorage;
};

export type NewVaultRequest = {
  worker: VaultWorker;
  result: NewVaultResult;
  navigate: NavigateFunction;
};

export type SecretRequest = {
  result: SecretInfo;
  owner: VaultStorage;
};

type LoadVaultsRequest = {
  user: User;
  worker: VaultWorker;
};

export const loadVaults = createAsyncThunk(
  "vaults/loadVaults",
  async (request: LoadVaultsRequest) => {
    const { user, worker } = request;
    const ids = await api.loadVaults(user);

    const buffers = ids.map(async (id) => {
      return await api.getVault(user, id);
    });

    const vaults = await Promise.all(buffers);
    const dict: any = {};
    for (const [index, id] of ids.entries()) {
      dict[id] = vaults[index];
    }

    const storage = Object.entries(dict).map(
      async (item: [string, ArrayBuffer]) => {
        const [id, buffer] = item;
        const vault: WebVault = await new (worker.WebVault as any)();
        try {
          await vault.importBuffer(Array.from(new Uint8Array(buffer)));
        } catch (e) {
          console.error(e);
        }

        return {
          uuid: id,
          label: id,
          vault,
          locked: true,
        };
      }
    );

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
    const meta = await vault.getMetaData();
    navigate(`/vault/${uuid}`);
    return { uuid, vault, label, locked: false, meta };
  }
);

export const createNewSecret = createAsyncThunk(
  "vaults/createNewSecret",
  async (request: SecretRequest) => {
    const { result, owner } = request;
    const { vault } = owner;
    await vault.create(result);
    const meta = await vault.getMetaData();
    return { ...owner, meta };
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
      state.current = payload;
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
    builder.addCase(createNewSecret.fulfilled, updateVaultFromThunk);
  },
});

export const { updateVault, setCurrent } = vaultsSlice.actions;
export const vaultsSelector = (state: { vaults: VaultState }) => state.vaults;
export default vaultsSlice.reducer;
