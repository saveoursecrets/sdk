// Represents a batch of changes that have been applied locally
// but not yet sent to the server.
//
// A batch of payloads may be converted to a PATCH request to the
// server to apply local changes to a remote vault.
import { createSlice, PayloadAction } from "@reduxjs/toolkit";
import { Payload } from "../types";

export type ChangeSet = {
  // Keys are the vault UUID identifier.
  [key: string]: Payload[];
};

export interface BatchState {
  changeSet: ChangeSet;
}

const initialState: BatchState = {
  changeSet: {},
};

const batchSlice = createSlice({
  name: "batch",
  initialState,
  reducers: {
    addBatchChange: (state, { payload }: PayloadAction<[string, Payload]>) => {
      const [vaultId, change] = payload;
      const changes = state.changeSet[vaultId]
        ? state.changeSet[vaultId].slice(0)
        : [];
      changes.push(change);
      state.changeSet = { ...state.changeSet, [vaultId]: changes };
    },
  },
});

export const { addBatchChange } = batchSlice.actions;
export const batchSelector = (state: { batch: BatchState }) => {
  const { changeSet } = state.batch;
  let totalChanges = 0;
  for (const changes of Object.values(changeSet)) {
    totalChanges += changes.length;
  }
  return { changeSet, totalChanges };
};
export default batchSlice.reducer;
