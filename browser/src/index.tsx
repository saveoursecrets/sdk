import React, { useMemo, useEffect, useState } from "react";
import * as ReactDOMClient from "react-dom/client";
import { HashRouter } from "react-router-dom";
import { Provider, useSelector } from "react-redux";

import useMediaQuery from "@mui/material/useMediaQuery";
import { ThemeProvider } from "@mui/material/styles";
import CssBaseline from "@mui/material/CssBaseline";

import { createTheme } from "@mui/material/styles";

import store from "./store";
import WorkerProvider, { WorkerContext, webWorker, worker } from "./worker-provider";
import { VaultWorker } from "./types";

import App from "./app";
import AuthenticatedApp from "./authenticated";
import { userSelector } from "./store/user";

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
}

function MainApp(props: AppProps) {
  const { worker } = props;
  const { user } = useSelector(userSelector);
  const [workerReady, setWorkerReady] = useState(false);

  //console.log("Main app rendering", worker);
  //console.log("Main app rendering", user);

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

  const onWorkerReady = (msg: any) => {
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

  console.log("Rendering app", workerReady);

  //return <AuthenticatedApp worker={worker} />;

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {user === null ? (
        <App worker={worker} />
      ) : (
        <AuthenticatedApp worker={worker} />
      )}
    </ThemeProvider>
  );
}

const root = ReactDOMClient.createRoot(document.querySelector("main"));
root.render(
  <React.StrictMode>
    <Provider store={store}>
      <HashRouter>
        <MainApp worker={worker} />
      </HashRouter>
    </Provider>
  </React.StrictMode>
);
