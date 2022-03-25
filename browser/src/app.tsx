import React from "react";
import { Routes, Route } from "react-router-dom";

import { styled } from "@mui/material/styles";
import Box from "@mui/material/Box";
import AppBar from "@mui/material/AppBar";
import Toolbar from "@mui/material/Toolbar";

import Typography from "@mui/material/Typography";
import IconButton from "@mui/material/IconButton";

import ChevronLeftIcon from "@mui/icons-material/ChevronLeft";
import ChevronRightIcon from "@mui/icons-material/ChevronRight";

import store from "./store";
import WorkerProvider, { WorkerContext } from "./worker-provider";
import { VaultWorker } from "./worker";
import LogoType from "./logotype";

import AppBarActions from "./app-bar-actions";

const NotFound = () => <h3>Page not found</h3>;

const Main = styled("div", { shouldForwardProp: (prop) => prop !== "open" })<{
  open?: boolean;
}>(({ theme }) => ({
  flexGrow: 1,
  padding: theme.spacing(3),
}));

//const Main = styled("div", {
//flexGrow: 1,
//padding: theme.spacing(3),
//});

interface AppProps {
  worker: VaultWorker;
}

export default function App(props: AppProps) {
  const { worker } = props;
  return (
    <Box sx={{ display: "flex", flexDirection: "column" }}>
      <AppBar position="relative">
        <Toolbar>
          <LogoType />
          <Typography
            variant="h6"
            component="div"
            sx={{ flexGrow: 1 }}
          ></Typography>

          <AppBarActions />
        </Toolbar>
      </AppBar>
      <Main>
        <Routes>
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Main>
    </Box>
  );
}
