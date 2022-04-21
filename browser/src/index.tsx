import React, { useMemo, useEffect, useState } from "react";
import * as ReactDOMClient from "react-dom/client";
import { HashRouter } from "react-router-dom";
import { Provider, useSelector } from "react-redux";

import useMediaQuery from "@mui/material/useMediaQuery";
import { ThemeProvider } from "@mui/material/styles";
import CssBaseline from "@mui/material/CssBaseline";

import { createTheme } from "@mui/material/styles";

import store from "./store";
import WorkerProvider, {
  WorkerContext,
  webWorker,
  worker,
} from "./worker-provider";
import { VaultWorker } from "./types";

import App from "./app";
import Snackbar from "./snackbar";
import AuthenticatedApp from "./authenticated";
import { accountSelector } from "./store/account";

declare module "@mui/material/styles" {
  interface Theme {
    status: {
      //danger: string;
    };
  }
  interface ThemeOptions {
    status?: {
      //danger?: string;
    };
  }
}

type AppProps = {
  worker: VaultWorker;
};

type WorkerMessage = {
  data: { ready: boolean };
};

function MainApp(props: AppProps) {
  const { worker } = props;
  const { account } = useSelector(accountSelector);
  const [workerReady, setWorkerReady] = useState(false);

  const verified = account !== null && Array.isArray(account.vaults);

  const prefersDarkMode = useMediaQuery("(prefers-color-scheme: dark)");
  const theme = useMemo(
    () =>
      createTheme({
        palette: {
          mode: prefersDarkMode ? "dark" : "light",
        },
      }),
    [prefersDarkMode]
  );

  const onWorkerReady = (msg: WorkerMessage) => {
    if (msg.data.ready) {
      setWorkerReady(true);
      webWorker.removeEventListener("message", onWorkerReady);
    }
  };

  useEffect(() => {
    webWorker.addEventListener("message", onWorkerReady);
  }, []);

  if (!workerReady) {
    return null;
  }

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      <>
        {verified ? (
          <AuthenticatedApp worker={worker} />
        ) : (
          <App worker={worker} />
        )}
        <Snackbar />
      </>
    </ThemeProvider>
  );
}

const root = ReactDOMClient.createRoot(document.querySelector("main"));
root.render(
  <Provider store={store}>
    <HashRouter>
      <WorkerProvider>
        <WorkerContext.Consumer>
          {(worker) => {
            return <MainApp worker={worker} />;
          }}
        </WorkerContext.Consumer>
      </WorkerProvider>
    </HashRouter>
  </Provider>
);
