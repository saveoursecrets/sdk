import * as React from "react";
import SpeedDial from "@mui/material/SpeedDial";
import SpeedDialIcon from "@mui/material/SpeedDialIcon";
import SpeedDialAction from "@mui/material/SpeedDialAction";

import FileIcon from "@mui/icons-material/FileOpen";
import AccountIcon from "@mui/icons-material/AccountBox";
import NoteIcon from "@mui/icons-material/Article";
import CredentialsIcon from "@mui/icons-material/List";

import { SecretKind } from "./types";

const actions = [
  { icon: <AccountIcon />, name: "Account Password", kind: SecretKind.Account },
  { icon: <NoteIcon />, name: "Secure Note", kind: SecretKind.Note },
  {
    icon: <CredentialsIcon />,
    name: "Credentials List",
    kind: SecretKind.Credentials,
  },
  { icon: <FileIcon />, name: "File Upload", kind: SecretKind.File },
];

interface NewSecretProps {
  onSelect: (kind: SecretKind) => void;
}

export default function NewSecretDial(props: NewSecretProps) {
  const { onSelect } = props;
  return (
    <SpeedDial
      ariaLabel="New secret"
      sx={{ position: "absolute", bottom: 16, right: 16 }}
      icon={<SpeedDialIcon />}
    >
      {actions.map((action) => (
        <SpeedDialAction
          key={action.name}
          icon={action.icon}
          tooltipTitle={action.name}
          onClick={() => onSelect(action.kind)}
        />
      ))}
    </SpeedDial>
  );
}
