import React from "react";
import { Routes, Route } from "react-router-dom";

import { styled } from "@mui/material/styles";
import Box from "@mui/material/Box";
import AppBar from "@mui/material/AppBar";
import Toolbar from "@mui/material/Toolbar";

import Stack from "@mui/material/Stack";

import { WorkerProps } from "./props";
import LogoType from "./logotype";

import AppBarActions from "./app-bar-actions";
import Home from "./home";
import Signup from "./signup";
import NotFound from "./not-found";

const Main = styled("div", { shouldForwardProp: (prop) => prop !== "open" })<{
  open?: boolean;
}>(({ theme }) => ({
  flexGrow: 1,
  padding: theme.spacing(3),
}));

export default function App(props: WorkerProps) {
  const { worker } = props;
  return (
    <Box sx={{ display: "flex", flexDirection: "column" }}>
      <AppBar position="relative">
        <Toolbar>
          <Stack
            sx={{ width: "100%" }}
            direction="row"
            justifyContent="space-between"
          >
            <LogoType />
            <AppBarActions />
          </Stack>
        </Toolbar>
      </AppBar>
      <Main>
        <Routes>
          <Route path="/" element={<Home />} />
          <Route path="/signup" element={<Signup worker={worker} />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </Main>
    </Box>
  );
}
