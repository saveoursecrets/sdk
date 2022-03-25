import React from "react";
import { Routes, Route } from "react-router-dom";

import { styled } from "@mui/material/styles";
import Box from "@mui/material/Box";
import AppBar from "@mui/material/AppBar";
import Toolbar from "@mui/material/Toolbar";

import Typography from "@mui/material/Typography";
import Stack from "@mui/material/Stack";

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

interface AppProps {
  worker: VaultWorker;
}

export default function App(props: AppProps) {
  //const { worker } = props;
  return (
    <Box sx={{ display: "flex", flexDirection: "column" }}>
      <AppBar position="relative">
        <Toolbar>

          <Stack sx={{width: '100%'}} direction="row" justifyContent="space-between">
            <LogoType />
            <AppBarActions />
          </Stack>
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
