import { configureStore } from "@reduxjs/toolkit";
import vaultsReducer from "./vaults";
import dialogsReducer from "./dialogs";
import userReducer from "./user";

const store = configureStore({
  reducer: {
    vaults: vaultsReducer,
    dialogs: dialogsReducer,
    user: userReducer,
  },
  middleware: (getDefaultMiddleware) =>
    getDefaultMiddleware({
      serializableCheck: {
        // Ignore these action types
        ignoredActions: [
          "vaults/setCurrent",
          "vaults/create/pending",
          "vaults/create/fulfilled",
          "vaults/lockAll/pending",
          "vaults/lockAll/fulfilled",
          "vaults/createNewSecureNote/pending",
          "vaults/createNewSecureNote/fulfilled",
          "vaults/createNewAccountPassword/pending",
          "vaults/createNewAccountPassword/fulfilled",
          "vaults/createNewCredentials/pending",
          "vaults/createNewCredentials/fulfilled",
        ],
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
