import React from "react";
import { useDispatch } from "react-redux";

import Box from "@mui/material/Box";
import Fab from "@mui/material/Fab";
import AddIcon from "@mui/icons-material/Add";

import { setDialogVisible, NEW_VAULT } from "../store/dialogs";

export default function Home() {
  const dispatch = useDispatch();

  const showNewVault = () => {
    dispatch(setDialogVisible([NEW_VAULT, true, null]));
  };

  return (
    <Box padding={2}>
      <p>Welcome!</p>

      <Fab
        onClick={showNewVault}
        color="primary"
        aria-label="add new vault"
        sx={{ position: "absolute", bottom: 16, right: 16 }}
      >
        <AddIcon />
      </Fab>
    </Box>
  );
}
