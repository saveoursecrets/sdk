import { configureStore } from "@reduxjs/toolkit";
import vaultsReducer from "./vaults";
import dialogsReducer from "./dialogs";
import userReducer from "./user";
import signupReducer from "./signup";
import snackbarReducer from "./snackbar";

const store = configureStore({
  reducer: {
    vaults: vaultsReducer,
    dialogs: dialogsReducer,
    user: userReducer,
    signup: signupReducer,
    snackbar: snackbarReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        // Ignore these action types
        ignoredActions: [
          "vaults/setCurrent",
          "vaults/updateVault",

          "vaults/loadVaults/pending",
          "vaults/loadVaults/fulfilled",
          "vaults/loadVaults/rejected",

          "vaults/create/pending",
          "vaults/create/fulfilled",
          "vaults/create/rejected",

          "vaults/lockAll/pending",
          "vaults/lockAll/fulfilled",
          "vaults/lockAll/rejected",

          "vaults/createSecret/pending",
          "vaults/createSecret/fulfilled",
          "vaults/createSecret/rejected",

          "vaults/readSecret/pending",
          "vaults/readSecret/fulfilled",
          "vaults/readSecret/rejected",

          "vaults/updateSecret/pending",
          "vaults/updateSecret/fulfilled",
          "vaults/updateSecret/rejected",

          "vaults/deleteSecret/pending",
          "vaults/deleteSecret/fulfilled",
          "vaults/deleteSecret/rejected",

          "signup/setSigner",
          "signup/setVault",

          "signup/new/pending",
          "signup/new/fulfilled",
          "signup/new/rejected",

          "signup/delete/pending",
          "signup/delete/fulfilled",
          "signup/delete/rejected",
        ],
        // Ignore these field paths in all actions
        ignoredActionPaths: [],
        // Ignore these paths in the state
        ignoredPaths: ["vaults", "signup"],
      },
    }),
});

export type RootState = ReturnType<typeof store.getState>;
export type AppDispatch = typeof store.dispatch;

export default store;
