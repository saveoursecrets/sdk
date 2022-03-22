import { createSlice, PayloadAction } from "@reduxjs/toolkit";
import { WebVault } from 'sos-wasm';

export interface VaultStorage {
  uuid: string;
  vault: WebVault;
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
    addVault: (state, { payload }: PayloadAction<VaultStorage>) => {
      state.vaults = [payload, ...state.vaults];
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
});

export const { addVault, updateVault } = vaultsSlice.actions;
export const vaultsSelector = (state: { vaults: VaultState }) =>
  state.vaults;
export default vaultsSlice.reducer;
