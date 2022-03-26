import React from "react";

import AccountIcon from "@mui/icons-material/AccountBox";
import NoteIcon from "@mui/icons-material/Article";
import CredentialsIcon from "@mui/icons-material/List";
import FileIcon from "@mui/icons-material/FileOpen";

import {SecretKind} from '../types';

interface SecretIconProps {
  kind: number;
}

export default function SecretIcon(props: SecretIconProps) {
  switch(props.kind) {
    case SecretKind.Account:
      return <AccountIcon />;
    case SecretKind.Note:
      return <NoteIcon />;
    case SecretKind.Credentials:
      return <CredentialsIcon />;
    case SecretKind.File:
      return <FileIcon />;
  }
}
