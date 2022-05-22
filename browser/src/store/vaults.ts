import {
  createSlice,
  createAsyncThunk,
  PayloadAction,
  isRejected,
  AnyAction,
} from "@reduxjs/toolkit";
import { NavigateFunction } from "react-router-dom";
import { WebVault } from "sos-wasm";

import api from "./api";
import {
  NewVaultResult,
  SecretMeta,
  SecretData,
  Account,
  VaultWorker,
  Summary,
  Payload,
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

export type CreateSecretRequest = {
  account: Account;
  result: SecretData;
  owner: VaultStorage;
};

export type ReadSecretRequest = {
  secretId: string;
  owner: VaultStorage;
};

export type UpdateSecretRequest = {
  account: Account;
  result: SecretData;
  owner: VaultStorage;
  navigate: NavigateFunction;
};

export type DeleteSecretRequest = {
  result: string;
  owner: VaultStorage;
  navigate: NavigateFunction;
};

type LoadVaultRequest = {
  summary: Summary;
  account: Account;
  worker: VaultWorker;
};

export const loadVault = createAsyncThunk(
  "vaults/loadVault",
  async (request: LoadVaultRequest) => {
    const { account, worker, summary } = request;
    const buffer = await api.getVault(account, summary.id);

    const vault: WebVault = await new (worker.WebVault as any)();
    await vault.importBuffer(Array.from(new Uint8Array(buffer)));

    return {
      uuid: summary.id,
      label: summary.name,
      vault,
      locked: true,
    };
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

export const createEmptyVault = async (worker: VaultWorker) => {
  /* eslint-disable @typescript-eslint/no-explicit-any */
  const vault: WebVault = await new (worker.WebVault as any)();
  return vault;
};

export const createNewVault = createAsyncThunk(
  "vaults/create",
  async (request: NewVaultRequest) => {
    const { worker, navigate, result } = request;
    const { name, label, password } = result;
    const vault = await createEmptyVault(worker);
    await vault.initialize(name, label, password);
    const uuid = await vault.id();
    const meta = await vault.getVaultMeta();
    navigate(`/vault/${uuid}`);
    return { uuid, vault, label, locked: false, meta };
  }
);

export const createSecret = createAsyncThunk(
  "vaults/createSecret",
  async (request: CreateSecretRequest) => {
    const { result, owner, account } = request;
    const { vault, uuid: vaultId } = owner;

    // Create the secret in the memory buffer
    const payload: Payload = await vault.create(result);
    const [secretId, encrypted] = payload.CreateSecret;

    // Send to the server for persistence
    const saved = await api.createSecret(account, vaultId, secretId, encrypted);
    if (!saved) {
      // FIXME: queue failed backend requests
      throw new Error(`failed to create secret: ${secretId}`);
    }

    console.log("Secret was saved", saved);

    // Update the vault meta data
    const meta = await vault.getVaultMeta();
    return { ...owner, meta };
  }
);

export const readSecret = createAsyncThunk(
  "vaults/readSecret",
  async (request: ReadSecretRequest) => {
    const { secretId, owner } = request;
    const { vault } = owner;
    return await vault.read(secretId);
  }
);

export const updateSecret = createAsyncThunk(
  "vaults/updateSecret",
  async (request: UpdateSecretRequest) => {
    const { result, account, navigate, owner } = request;
    const { uuid: vaultId, vault } = owner;
    const payload: Payload = await vault.update(result);
    const [secretId, encrypted] = payload.UpdateSecret;

    // Send to the server for persistence
    const saved = await api.updateSecret(account, vaultId, secretId, encrypted);
    if (!saved) {
      // FIXME: queue failed backend requests
      throw new Error(`failed to update secret: ${secretId}`);
    }

    console.log("Secret was updated", saved);

    // Update the vault meta data and navigate to refresh
    // the view
    const meta = await vault.getVaultMeta();
    const random = Math.random();
    navigate(`/vault/${vaultId}/${result.secretId}?refresh=${random}`);
    return { ...owner, meta };
  }
);

export const deleteSecret = createAsyncThunk(
  "vaults/deleteSecret",
  async (request: DeleteSecretRequest) => {
    const { result, navigate, owner } = request;
    const { uuid, vault } = owner;
    await vault.delete(result);
    const meta = await vault.getVaultMeta();
    navigate(`/vault/${uuid}`);
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

const logError = (state: VaultState, action: AnyAction) => {
  //console.error(action.error);
  throw action.error;
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
    builder.addCase(loadVault.fulfilled, (state, action) => {
      const vaults = [...state.vaults];
      vaults.push(action.payload);
      state.vaults = vaults;
    });
    builder.addCase(lockAll.fulfilled, (state, action) => {
      state.vaults = action.payload;
    });
    builder.addCase(createSecret.fulfilled, updateVaultFromThunk);
    builder.addCase(updateSecret.fulfilled, updateVaultFromThunk);
    builder.addCase(deleteSecret.fulfilled, updateVaultFromThunk);

    builder.addMatcher(isRejected, logError);
  },
});

export const { updateVault, setCurrent } = vaultsSlice.actions;
export const vaultsSelector = (state: { vaults: VaultState }) => state.vaults;
export default vaultsSlice.reducer;
