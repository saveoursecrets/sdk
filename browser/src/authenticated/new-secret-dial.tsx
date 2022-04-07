import * as React from "react";
import { useDispatch } from "react-redux";
import SpeedDial from "@mui/material/SpeedDial";
import SpeedDialIcon from "@mui/material/SpeedDialIcon";
import SpeedDialAction from "@mui/material/SpeedDialAction";

import FileIcon from "@mui/icons-material/FileOpen";
import AccountIcon from "@mui/icons-material/AccountBox";
import NoteIcon from "@mui/icons-material/Article";
import CredentialsIcon from "@mui/icons-material/List";

import { SecretKind } from "../types";

import {
  setDialogVisible,
  NEW_SECURE_NOTE,
  NEW_ACCOUNT_PASSWORD,
  NEW_CREDENTIALS,
  NEW_FILE_UPLOAD,
} from "../store/dialogs";

const actions = [
  {
    icon: <AccountIcon />,
    name: "Account Password",
    kind: SecretKind.Account,
  },
  {
    icon: <NoteIcon />,
    name: "Secure Note",
    kind: SecretKind.Note,
  },
  {
    icon: <CredentialsIcon />,
    name: "Credentials List",
    kind: SecretKind.Credentials,
  },
  {
    icon: <FileIcon />,
    name: "File Upload",
    kind: SecretKind.File,
  },
];

interface NewSecretProps {
  onSelect: (kind: SecretKind) => void;
}

export default function NewSecretDial(props: NewSecretProps) {
  const dispatch = useDispatch();

  const createNewSecret = (kind: SecretKind) => {
    console.log("create new secret", kind);
    switch (kind) {
      case SecretKind.Account:
        dispatch(setDialogVisible([NEW_ACCOUNT_PASSWORD, true]));
        break;
      case SecretKind.Note:
        dispatch(setDialogVisible([NEW_SECURE_NOTE, true]));
        break;
      case SecretKind.Credentials:
        dispatch(setDialogVisible([NEW_CREDENTIALS, true]));
        break;
      case SecretKind.File:
        dispatch(setDialogVisible([NEW_FILE_UPLOAD, true]));
        break;
    }
  };

  return (
    <SpeedDial
      ariaLabel="New secret"
      sx={{ position: "fixed", bottom: 16, right: 16 }}
      icon={<SpeedDialIcon />}
    >
      {actions.map((action) => (
        <SpeedDialAction
          key={action.name}
          icon={action.icon}
          tooltipTitle={action.name}
          onClick={() => createNewSecret(action.kind)}
        />
      ))}
    </SpeedDial>
  );
}
