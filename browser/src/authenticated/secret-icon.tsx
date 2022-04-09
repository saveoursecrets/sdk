import React from "react";

import AccountIcon from "@mui/icons-material/AccountBox";
import NoteIcon from "@mui/icons-material/Article";
import CredentialsIcon from "@mui/icons-material/List";
import FileIcon from "@mui/icons-material/FileOpen";

import { SecretKind } from "../types";

interface SecretIconProps {
  kind: number;
  fontSize?: string;
}

export default function SecretIcon(props: SecretIconProps) {
  const { kind, fontSize } = props;
  switch (kind) {
    case SecretKind.Account:
      return <AccountIcon fontSize={fontSize} />;
    case SecretKind.Note:
      return <NoteIcon fontSize={fontSize} />;
    case SecretKind.Credentials:
      return <CredentialsIcon fontSize={fontSize} />;
    case SecretKind.File:
      return <FileIcon fontSize={fontSize} />;
  }
}
