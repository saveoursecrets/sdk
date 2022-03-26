import React, { useState } from "react";

import IconButton from "@mui/material/IconButton";
import FormControl from "@mui/material/FormControl";
import InputLabel from "@mui/material/InputLabel";
import OutlinedInput from "@mui/material/OutlinedInput";
import InputAdornment from "@mui/material/InputAdornment";

import Visibility from "@mui/icons-material/Visibility";
import VisibilityOff from "@mui/icons-material/VisibilityOff";

interface ViewablePasswordProps {
  id: string;
  label?: string;
  value: string;
  placeholder?: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  error: boolean;
}

export default function ViewablePassword(props: ViewablePasswordProps) {
  const { id, label, value, placeholder, onChange, error } = props;
  const [showPassword, setShowPassword] = useState(false);

  const toggleShowPassword = () => {
    setShowPassword(!showPassword);
  };

  const onMouseDownPassword = (event: React.MouseEvent<HTMLElement>) => {
    event.preventDefault();
  };

  return (
    <FormControl error={error} variant="outlined">
      <InputLabel error={error} htmlFor={id}>
        {label} *
      </InputLabel>
      <OutlinedInput
        id={id}
        label={label}
        type={showPassword ? "text" : "password"}
        value={value}
        onChange={onChange}
        error={error}
        placeholder={placeholder}
        autoComplete="off"
        required
        endAdornment={
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
        }
      />
    </FormControl>
  );
}
