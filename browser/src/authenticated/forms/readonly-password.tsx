import React, { useState } from "react";

import Stack from "@mui/material/Stack";
import Box from "@mui/material/Box";
import IconButton from "@mui/material/IconButton";
import Button from "@mui/material/Button";
import FormControl from "@mui/material/FormControl";
import InputLabel from "@mui/material/InputLabel";
import Input from "@mui/material/Input";
import Tooltip from "@mui/material/Tooltip";

import ContentCopyIcon from "@mui/icons-material/ContentCopy";

import PasswordAdornment from "./password-adornment";

import { copyToClipboard } from "../../utils";

interface ReadOnlyPasswordProps {
  value: string;
  compact: boolean;
}

export default function ReadOnlyPassword(props: ReadOnlyPasswordProps) {
  const { value, compact } = props;
  const [showPassword, setShowPassword] = useState(false);

  const copy = compact ? (
    <Tooltip title="Copy to clipboard">
      <IconButton onClick={async (e) => await copyToClipboard(e, value)}>
        <ContentCopyIcon />
      </IconButton>
    </Tooltip>
  ) : (
    <Stack alignItems="center" flex={1}>
      <Tooltip title="Copy to clipboard">
        <Button
          startIcon={<ContentCopyIcon />}
          onClick={async (e) => await copyToClipboard(e, value)}
        >
          Copy to clipboard
        </Button>
      </Tooltip>
    </Stack>
  );

  return (
    <Stack spacing={2} direction={compact ? "row" : "column"} flex={1}>
      <Input
        disabled
        type={showPassword ? "text" : "password"}
        value={value}
        autoComplete="off"
        sx={{ width: "100%" }}
        endAdornment={<PasswordAdornment onChange={setShowPassword} />}
      />
      {copy}
    </Stack>
  );
}
