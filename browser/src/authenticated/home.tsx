import React from "react";
import { useDispatch } from "react-redux";

import Fab from "@mui/material/Fab";
import AddIcon from "@mui/icons-material/Add";

import { setDialogVisible, NEW_VAULT } from "../store/dialogs";

import { NoteForm } from "./secrets";

export default function Home() {
  const dispatch = useDispatch();

  const showNewVault = () => {
    dispatch(setDialogVisible([NEW_VAULT, true]));
  };

  return (
    <>
      <p>Welcome!</p>

      <NoteForm label="" note="" onFormSubmit={() => {}} />

      <Fab
        onClick={showNewVault}
        color="primary"
        aria-label="add new vault"
        sx={{ position: "absolute", bottom: 16, right: 16 }}
      >
        <AddIcon />
      </Fab>
    </>
  );
}
