import {
  createSlice,
  createAsyncThunk,
  PayloadAction,
  isRejected,
  AnyAction,
} from "@reduxjs/toolkit";
import { NavigateFunction } from "react-router-dom";
import { WebVault } from "sos-wasm";

import { AppDispatch, RootState } from ".";
import { addBatchChange, clearBatchChanges } from "./batch";

import api from "./api";
import {
  ConflictOperation,
  Conflict,
  ConflictHandlers,
  NewVaultResult,
  SecretMeta,
  Secret,
  SecretData,
  Account,
  VaultWorker,
  Summary,
  Payload,
  ChangeSet,
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
  // Current secret being viewed.
  //
  // We want to put this in VaultStorage but trying to update
  // VaultStorage with a new secret produces an obscure redux/immer error.
  secret?: [SecretMeta, Secret];
};

export type NewVaultRequest = {
  worker: VaultWorker;
  result: NewVaultResult;
  navigate: NavigateFunction;
};

export type CreateSecretRequest = {
  account: Account;
  result: SecretData;
  storage: VaultStorage;
};

export type ReadSecretRequest = {
  account: Account;
  secretId: string;
  storage: VaultStorage;
};

export type UpdateSecretRequest = {
  account: Account;
  result: SecretData;
  storage: VaultStorage;
  navigate: NavigateFunction;
};

export type DeleteSecretRequest = {
  account: Account;
  result: string;
  storage: VaultStorage;
  navigate: NavigateFunction;
};

type SyncRequest = {
  account: Account;
  worker: VaultWorker;
  changeSet: ChangeSet;
};

type LoadVaultRequest = {
  summary: Summary;
  account: Account;
  worker: VaultWorker;
};

type PullVaultRequest = {
  account: Account;
  storage: VaultStorage;
};

type PushVaultRequest = {
  account: Account;
  storage: VaultStorage;
  changeSequence: number;
};

const makeConflictHandlers = (
  dispatch: AppDispatch,
  account: Account,
  storage: VaultStorage,
  changeSequence: number,
  replay: () => Promise<unknown>
): ConflictHandlers => {
  return {
    pull: async () => {
      const request = { account, storage };
      await dispatch(pullVault(request));
    },
    push: async () => {
      const request = { account, storage, changeSequence };
      await dispatch(pushVault(request));
    },
    replay,
    queue: async (changes: [string, Payload]) => {
      await dispatch(addBatchChange(changes));
    },
  };
};

const makeNetworkGuard = async (
  request: Promise<Response>,
  handleError: (e: Error) => void
): Promise<Response | null> => {
  try {
    return await request;
  } catch (e) {
    handleError(e);
  }
};

// Compare a local and remote change sequence and perform the
// appropriate action depending upon which is ahead or behind
// the other.
const resolveConflict = async (
  conflict: Conflict,
  handlers: ConflictHandlers
): Promise<void> => {
  const { operation, changePair } = conflict;
  const { local, remote } = changePair;

  // Account for the fact that the local version of the vault
  // has been updated before receiving the conflict response
  let nextRemoteSequence = remote;
  switch (operation) {
    case ConflictOperation.CREATE_SECRET:
    case ConflictOperation.UPDATE_SECRET:
    case ConflictOperation.DELETE_SECRET:
      nextRemoteSequence = remote + 1;
      break;
  }

  // In theory the remote sequence and local sequence
  // should never be equal assuming the server is handling
  // conflicts correctly, however we check to ensure either
  // ahead or behind as equality should be a noop.
  if (nextRemoteSequence !== local) {
    const isRemoteAhead = nextRemoteSequence > local;
    if (isRemoteAhead) {
      await handlers.pull();
      await handlers.replay();
    } else {
      await handlers.push();
    }
  }
};

// Attempt to patch all vaults that have local changesets
// that have not been sent to the server yet.
export const syncChangeSet = createAsyncThunk<
  void,
  SyncRequest,
  { getState: () => RootState; dispatch: AppDispatch }
>("vaults/syncChangeSet", async (request, { getState, dispatch }) => {
  const state = getState() as RootState;
  const { vaults } = state.vaults;
  const { account, worker, changeSet } = request;
  for (const [vaultId, changes] of Object.entries(changeSet)) {
    // Get the binary encoded data to send to the server
    const patch = await worker.patch(changes);
    // Locate the current vault to determine the current change sequence
    const storage = vaults.find((v) => v.uuid === vaultId);
    if (storage) {
      // Ensure we get also send the current change sequence
      const changeSequence = await storage.vault.changeSequence();
      console.log("sync", vaultId, changeSequence);
      // Try to apply the patch
      const response = await makeNetworkGuard(api.patchVault(
        account,
        vaultId,
        patch,
        changeSequence
      ), (e: Error) => {
        // FIXME: show UI notification that the sync failed
        throw e;
      });
      if (response.ok) {
        // Patch success so we can clear those changes
        await dispatch(clearBatchChanges(vaultId));
      }
    } else {
      throw new Error(`sync failed to find vault storage: ${vaultId}`);
    }
  }
});

export const loadVault = createAsyncThunk(
  "vaults/loadVault",
  async (request: LoadVaultRequest) => {
    const { account, worker, summary } = request;
    const buffer = await api.getVault(account, summary.id);

    /* eslint-disable @typescript-eslint/no-explicit-any */
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

export const pullVault = createAsyncThunk(
  "vaults/pull",
  async (request: PullVaultRequest) => {
    const { account, storage } = request;
    const buffer = await api.getVault(account, storage.uuid);
    const { vault } = storage;
    await vault.importBuffer(Array.from(new Uint8Array(buffer)));
    // Update the vault meta data
    const meta = await vault.getVaultMeta();
    return { ...storage, meta };
  }
);

export const pushVault = createAsyncThunk(
  "vaults/push",
  async (request: PushVaultRequest) => {
    const { account, storage, changeSequence } = request;
    const { vault } = storage;
    const buffer = await vault.buffer();
    await api.saveVault(account, storage.uuid, buffer, changeSequence);
    return storage;
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

export const createSecret = createAsyncThunk<
  VaultStorage | null,
  CreateSecretRequest,
  { dispatch: AppDispatch }
>("vaults/createSecret", async (request, { dispatch }) => {
  const { result, storage, account } = request;
  const { vault } = storage;

  // Create the secret in the memory buffer
  const payload: Payload = await vault.create(result);
  const [changeSequence] = payload.CreateSecret;

  // Attempt to save on the remote server
  const handlers = makeConflictHandlers(
    dispatch,
    account,
    storage,
    changeSequence,
    async () => {
      console.log("retry the create operation!!");
      await dispatch(createSecret(request));
    }
  );
  syncCreateSecret(account, storage, payload, handlers);

  // Update the vault meta data
  const meta = await vault.getVaultMeta();
  return { ...storage, meta };
});

// Attempt to send the create secret payload to the server.
const syncCreateSecret = async (
  account: Account,
  storage: VaultStorage,
  payload: Payload,
  handlers: ConflictHandlers
): Promise<Response | null> => {
  const [changeSequence, secretId, encrypted] = payload.CreateSecret;
  const { uuid: vaultId } = storage;

  // Send to the server for persistence
  const response = await makeNetworkGuard(
    api.createSecret(account, changeSequence, vaultId, secretId, encrypted),
    (e: Error) => {
      handlers.queue([vaultId, payload]);
    }
  );

  if (!response) {
    return null;
  }

  if (response.status === 409) {
    const remoteChangeSequence = parseInt(
      response.headers.get("x-change-sequence")
    );
    console.log("handling conflict", remoteChangeSequence);
    const conflict = {
      operation: ConflictOperation.CREATE_SECRET,
      changePair: {
        local: changeSequence,
        remote: remoteChangeSequence,
      },
      vaultId,
      secretId,
    };
    console.log("handle conflict in create operation", conflict);

    await resolveConflict(conflict, handlers);
    return null;
  } else if (!response.ok) {
    // Queue failed backend requests
    await handlers.queue([vaultId, payload]);
    return null;
  }

  console.log("Secret was saved", response.ok);

  return response;
};

export const readSecret = createAsyncThunk<
  [SecretMeta, Secret] | null,
  ReadSecretRequest,
  { dispatch: AppDispatch }
>("vaults/readSecret", async (request, { dispatch }) => {
  const { account, secretId, storage } = request;
  const { vault } = storage;
  const result: [SecretMeta, Secret, Payload] = await vault.read(secretId);
  const [meta, secret, payload] = result;
  const [changeSequence] = payload.ReadSecret;

  // Attempt to save on the remote server
  const handlers = makeConflictHandlers(
    dispatch,
    account,
    storage,
    changeSequence,
    async () => {
      console.log("retry the read operation!!");
      await dispatch(readSecret(request));
    }
  );
  syncReadSecret(account, storage, payload, handlers);

  return [meta, secret];
});

const syncReadSecret = async (
  account: Account,
  storage: VaultStorage,
  payload: Payload,
  handlers: ConflictHandlers
): Promise<Response | null> => {
  const { uuid: vaultId } = storage;
  const [changeSequence, secretId] = payload.ReadSecret;

  // Send to the server for the audit log
  const response = await makeNetworkGuard(
    api.readSecret(account, changeSequence, vaultId, secretId),
    (e: Error) => {
      handlers.queue([vaultId, payload]);
    }
  );

  if (!response) {
    return null;
  }

  if (response.status === 409) {
    const remoteChangeSequence = parseInt(
      response.headers.get("x-change-sequence")
    );
    const conflict = {
      operation: ConflictOperation.READ_SECRET,
      changePair: {
        local: changeSequence,
        remote: remoteChangeSequence,
      },
      vaultId,
      secretId,
    };
    console.log("handle conflict in read operation", conflict);

    await resolveConflict(conflict, handlers);
    return null;
  } else if (!response.ok) {
    await handlers.queue([vaultId, payload]);
    return null;
  }

  console.log("Secret was read", response.ok, response.status, response);

  return response;
};

export const updateSecret = createAsyncThunk<
  VaultStorage,
  UpdateSecretRequest,
  { dispatch: AppDispatch }
>("vaults/updateSecret", async (request, { dispatch }) => {
  const { result, account, navigate, storage } = request;
  const { uuid: vaultId, vault } = storage;
  const payload: Payload = await vault.update(result);
  if (payload) {
    const [changeSequence, secretId] = payload.UpdateSecret;

    // Attempt to save on the remote server
    const handlers = makeConflictHandlers(
      dispatch,
      account,
      storage,
      changeSequence,
      async () => {
        console.log("retry the update operation!!");
        await dispatch(updateSecret(request));
      }
    );
    syncUpdateSecret(account, storage, payload, handlers);

    // Update the vault meta data and navigate to refresh
    // the view
    const meta = await vault.getVaultMeta();
    const random = Math.random();
    navigate(`/vault/${vaultId}/${secretId}?refresh=${random}`);
    return { ...storage, meta };
  }
  return storage;
});

const syncUpdateSecret = async (
  account: Account,
  storage: VaultStorage,
  payload: Payload,
  handlers: ConflictHandlers
): Promise<Response | null> => {
  const { uuid: vaultId } = storage;
  const [changeSequence, secretId, encrypted] = payload.UpdateSecret;

  // Send to the server for persistence
  const response = await api.updateSecret(
    account,
    changeSequence,
    vaultId,
    secretId,
    encrypted
  );

  if (response.status === 409) {
    const remoteChangeSequence = parseInt(
      response.headers.get("x-change-sequence")
    );
    console.log("handling conflict", remoteChangeSequence);
    const conflict = {
      operation: ConflictOperation.UPDATE_SECRET,
      changePair: {
        local: changeSequence,
        remote: remoteChangeSequence,
      },
      vaultId,
      secretId,
    };
    console.log("handle conflict in update operation", conflict);

    await resolveConflict(conflict, handlers);
    return null;
  } else if (!response.ok) {
    // Queue failed backend requests
    await handlers.queue([vaultId, payload]);
    return null;
  }

  console.log("Secret was updated", response.ok);
};

export const deleteSecret = createAsyncThunk<
  VaultStorage,
  DeleteSecretRequest,
  { dispatch: AppDispatch }
>("vaults/deleteSecret", async (request, { dispatch }) => {
  const { result, account, navigate, storage } = request;
  const { uuid: vaultId, vault } = storage;
  const payload: Payload = await vault.delete(result);
  if (payload) {
    const [changeSequence] = payload.DeleteSecret;

    // Attempt to save on the remote server
    const handlers = makeConflictHandlers(
      dispatch,
      account,
      storage,
      changeSequence,
      async () => {
        console.log("retry the delete operation!!");
        await dispatch(deleteSecret(request));
      }
    );
    syncDeleteSecret(account, storage, payload, handlers);

    // Update the vault meta data
    const meta = await vault.getVaultMeta();
    navigate(`/vault/${vaultId}`);
    return { ...storage, meta };
  }
  return storage;
});

const syncDeleteSecret = async (
  account: Account,
  storage: VaultStorage,
  payload: Payload,
  handlers: ConflictHandlers
): Promise<Response | null> => {
  const { uuid: vaultId } = storage;
  const [changeSequence, secretId] = payload.DeleteSecret;

  // Send to the server for persistence
  const response = await api.deleteSecret(
    account,
    changeSequence,
    vaultId,
    secretId
  );

  if (response.status === 409) {
    const remoteChangeSequence = parseInt(
      response.headers.get("x-change-sequence")
    );
    console.log("handling conflict", remoteChangeSequence);
    const conflict = {
      operation: ConflictOperation.DELETE_SECRET,
      changePair: {
        local: changeSequence,
        remote: remoteChangeSequence,
      },
      vaultId,
      secretId,
    };
    console.log("handle conflict in delete operation", conflict);

    await resolveConflict(conflict, handlers);
    return null;
  } else if (!response.ok) {
    // Queue failed backend requests
    await handlers.queue([vaultId, payload]);
    return null;
  }

  console.log("Secret was deleted", response.ok);

  return response;
};

const initialState: VaultState = {
  vaults: [],
  current: null,
  secret: null,
};

const updateVaultFromThunk = (
  state: VaultState,
  action: PayloadAction<VaultStorage | null>
) => {
  const { payload } = action;
  if (payload) {
    state.current = payload;
    state.vaults = state.vaults.map((prop: VaultStorage) => {
      if (payload.uuid === prop.uuid) {
        return payload;
      } else {
        return prop;
      }
    });
  }
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
      state.secret = null;
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
      state.secret = null;
    });
    builder.addCase(loadVault.fulfilled, (state, action) => {
      const vaults = [...state.vaults];
      vaults.push(action.payload);
      state.vaults = vaults;
    });
    builder.addCase(lockAll.fulfilled, (state, action) => {
      state.vaults = action.payload;
    });
    builder.addCase(pullVault.fulfilled, updateVaultFromThunk);
    builder.addCase(createSecret.fulfilled, updateVaultFromThunk);
    builder.addCase(
      readSecret.fulfilled,
      (
        state: VaultState,
        action: PayloadAction<[SecretMeta, Secret] | null>
      ) => {
        const { payload } = action;
        if (payload) {
          state.secret = payload;
        }
      }
    );
    builder.addCase(updateSecret.fulfilled, updateVaultFromThunk);
    builder.addCase(deleteSecret.fulfilled, updateVaultFromThunk);

    builder.addMatcher(isRejected, logError);
  },
});

export const { updateVault, setCurrent } = vaultsSlice.actions;
export const vaultsSelector = (state: { vaults: VaultState }) => state.vaults;
export const secretSelector = (state: { vaults: VaultState }) =>
  state.vaults.secret;
export default vaultsSlice.reducer;
