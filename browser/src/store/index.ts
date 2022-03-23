import { configureStore } from "@reduxjs/toolkit";
import vaultsReducer from "./vaults";

const store = configureStore({
  reducer: {
    vaults: vaultsReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        // Ignore these action types
        ignoredActions: ["vaults/addVault", "vaults/updateVault"],
        // Ignore these field paths in all actions
        ignoredActionPaths: [],
        // Ignore these paths in the state
        ignoredPaths: ["vaults"],
      },
    }),
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;

export default store;
