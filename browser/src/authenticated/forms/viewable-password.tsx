import React, { useState } from "react";

import FormControl from "@mui/material/FormControl";
import InputLabel from "@mui/material/InputLabel";
import OutlinedInput from "@mui/material/OutlinedInput";
import PasswordAdornment from "./password-adornment";

interface ViewablePasswordProps {
  id: string;
  label?: string;
  value: string;
  placeholder?: string;
  onChange: (e: React.ChangeEvent<HTMLInputElement>) => void;
  error: boolean;
  disabled: boolean;
}

export default function ViewablePassword(props: ViewablePasswordProps) {
  const { id, label, value, disabled, placeholder, onChange, error } = props;
  const [showPassword, setShowPassword] = useState(false);

  return (
    <FormControl error={error} variant="outlined">
      <InputLabel error={error} htmlFor={id} disabled={disabled}>
        {label} *
      </InputLabel>
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
        endAdornment={<PasswordAdornment onChange={setShowPassword} />}
      />
    </FormControl>
  );
}
