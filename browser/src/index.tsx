import React from "react";
import ReactDOM from "react-dom";
import { HashRouter } from "react-router-dom";
import { Provider, useSelector } from "react-redux";

import { ThemeProvider } from "@mui/material/styles";
import CssBaseline from "@mui/material/CssBaseline";

import { createTheme } from "@mui/material/styles";

import store from "./store";
import WorkerProvider, { WorkerContext } from "./worker-provider";
import { VaultWorker } from "./worker";

import App from "./app";
import AuthenticatedApp from "./authenticated";
import Dialogs from "./dialogs";
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

const theme = createTheme({
  palette: {
    mode: "dark",
  },
  status: {
    //danger: orange[500],
  },
});

interface AppProps {
  worker: VaultWorker;
}

function MainApp(props: AppProps) {
  const { worker } = props;
  const { token } = useSelector(userSelector);

  return (
    <>
      <CssBaseline />
      {token === null ? (
        <App worker={worker} />
      ) : (
        <AuthenticatedApp worker={worker} />
      )}
      <Dialogs worker={worker} />
    </>
  );
}

ReactDOM.render(
  <React.StrictMode>
    <Provider store={store}>
      <HashRouter>
        <ThemeProvider theme={theme}>
          <WorkerProvider>
            <WorkerContext.Consumer>
              {(worker) => {
                return <MainApp worker={worker} />;
              }}
            </WorkerContext.Consumer>
          </WorkerProvider>
        </ThemeProvider>
      </HashRouter>
    </Provider>
  </React.StrictMode>,
  document.querySelector("main")
);
