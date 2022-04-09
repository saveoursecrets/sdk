import React, { useState } from "react";

import IconButton from "@mui/material/IconButton";
import FormControl from "@mui/material/FormControl";
import InputLabel from "@mui/material/InputLabel";
import OutlinedInput from "@mui/material/OutlinedInput";
import Input from "@mui/material/Input";
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
  disabled: boolean;
  showLabel: boolean;
}

export default function ViewablePassword(props: ViewablePasswordProps) {
  const {
    id,
    label,
    showLabel,
    value,
    disabled,
    placeholder,
    onChange,
    error,
  } = props;
  const [showPassword, setShowPassword] = useState(false);

  const toggleShowPassword = () => {
    setShowPassword(!showPassword);
  };

  const onMouseDownPassword = (event: React.MouseEvent<HTMLElement>) => {
    event.preventDefault();
  };

  const variant = showLabel ? "outlined" : "standard";

  const endAdornment = (
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

  return (
    <FormControl error={error} variant={variant}>
      {showLabel ? (
        <InputLabel error={error} htmlFor={id} disabled={disabled}>
          {label} *
        </InputLabel>
      ) : null}

      {showLabel ? (
        <OutlinedInput
          id={id}
          label={label}
          disabled={disabled}
          type={showPassword ? "text" : "password"}
          value={value}
          onChange={onChange}
          error={error}
          placeholder={placeholder}
          autoComplete="off"
          required
          endAdornment={endAdornment}
        />
      ) : (
        <Input
          id={id}
          label={label}
          type={showPassword ? "text" : "password"}
          value={value}
          onChange={onChange}
          error={error}
          placeholder={placeholder}
          autoComplete="off"
          required
          endAdornment={endAdornment}
        />
      )}
    </FormControl>
  );
}
