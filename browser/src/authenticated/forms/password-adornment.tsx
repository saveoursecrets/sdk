import React, { useState } from "react";

import IconButton from "@mui/material/IconButton";
import InputAdornment from "@mui/material/InputAdornment";

import Visibility from "@mui/icons-material/Visibility";
import VisibilityOff from "@mui/icons-material/VisibilityOff";

type PasswordAdornmentProps = {
  onChange: (value: boolean) => void;
};

export default function PasswordAdornment(props: PasswordAdornmentProps) {
  const { onChange } = props;
  const [showPassword, setShowPassword] = useState(false);

  const toggleShowPassword = () => {
    const value = !showPassword;
    setShowPassword(value);
    onChange(value);
  };

  const onMouseDownPassword = (event: React.MouseEvent<HTMLElement>) => {
    event.preventDefault();
  };

  return (
    <InputAdornment position="end">
      <IconButton
        aria-label="toggle password visibility"
        onClick={toggleShowPassword}
        onMouseDown={onMouseDownPassword}
        edge="end"
      >
        {showPassword ? <VisibilityOff /> : <Visibility />}
      </IconButton>
    </InputAdornment>
  );
}
