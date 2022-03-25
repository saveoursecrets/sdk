import React, {useMemo} from "react";
import ReactDOM from "react-dom";
import { HashRouter } from "react-router-dom";
import { Provider, useSelector } from "react-redux";

import useMediaQuery from '@mui/material/useMediaQuery';
import { ThemeProvider } from "@mui/material/styles";
import CssBaseline from "@mui/material/CssBaseline";

import { createTheme } from "@mui/material/styles";

import store from "./store";
import WorkerProvider, { WorkerContext } from "./worker-provider";
import { VaultWorker } from "./worker";

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

interface AppProps {
  worker: VaultWorker;
}

function MainApp(props: AppProps) {
  const { worker } = props;
  const { token } = useSelector(userSelector);

  const prefersDarkMode = useMediaQuery('(prefers-color-scheme: dark)');
  const theme = useMemo(
    () =>
      createTheme({
        palette: {
          mode: prefersDarkMode ? 'dark' : 'light',
        },
      }),
    [prefersDarkMode],
  );

  return (
    <ThemeProvider theme={theme}>
      <CssBaseline />
      {token === null ? (
        <App worker={worker} />
      ) : (
        <AuthenticatedApp worker={worker} />
      )}
    </ThemeProvider>
  );
}

ReactDOM.render(
  <React.StrictMode>
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
  </React.StrictMode>,
  document.querySelector("main")
);
