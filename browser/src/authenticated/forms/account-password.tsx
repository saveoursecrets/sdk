import React, { useState } from "react";

import Stack from "@mui/material/Stack";
import TextField from "@mui/material/TextField";

import ViewablePassword from "./viewable-password";

import { SecretData, SecretKind, AccountSecret } from "../../types";

interface AccountPasswordFormProps {
  onFormSubmit: (result: SecretData) => void;
  secret?: SecretData;
}

export default function AccountPasswordForm(props: AccountPasswordFormProps) {
  const { onFormSubmit, secret } = props;

  const initialLabel = secret && secret.meta.label;
  const initialAccount = secret && (secret.secret as AccountSecret).account;
  const initialUrl = secret && (secret.secret as AccountSecret).url;
  const initialPassword = secret && (secret.secret as AccountSecret).password;

  const [label, setLabel] = useState(initialLabel || "");
  const [labelError, setLabelError] = useState(false);

  const [account, setAccount] = useState(initialAccount || "");
  const [accountError, setAccountError] = useState(false);

  const [url, setUrl] = useState(initialUrl || "");
  const [urlError, setUrlError] = useState(false);

  const [password, setPassword] = useState(initialPassword || "");
  const [passwordError, setPasswordError] = useState(false);

  const onLabelChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setLabel(e.target.value);

  const onAccountChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setAccount(e.target.value);

  const onUrlChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setUrl(e.target.value);

  const onPasswordChange = (e: React.ChangeEvent<HTMLInputElement>) =>
    setPassword(e.target.value);

  const onSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();

    setLabelError(false);
    setAccountError(false);
    setUrlError(false);
    setPasswordError(false);

    // Validation of optional URL field
    let urlIsValid: boolean = url === "" ? true : false;
    if (!urlIsValid) {
      try {
        new URL(url);
        urlIsValid = true;
      } catch (e) {
        urlIsValid = false;
      }
    }

    if (label.trim() === "") {
      setLabelError(true);
      setLabel("");
    } else if (account.trim() === "") {
      setAccountError(true);
      setAccount("");
    } else if (!urlIsValid) {
      setUrlError(true);
    } else if (password.trim() === "") {
      setPasswordError(true);
      setPassword("");
    } else {
      const info: SecretData = {
        secretId: secret && secret.secretId,
        meta: {
          label,
          kind: SecretKind.Account,
        },
        secret: { account, url, password },
      };
      onFormSubmit(info);
    }
  };

  return (
    <form id="account-password-form" onSubmit={onSubmit} noValidate>
      <Stack spacing={2} sx={{ paddingTop: 1 }}>
        <TextField
          id="secret-label"
          label="Name"
          placeholder="Enter a secret name"
          required
          autoFocus
          onChange={onLabelChange}
          value={label}
          error={labelError}
        />
        <TextField
          id="account-name"
          label="Account Name"
          placeholder="Enter the name of the account"
          required
          onChange={onAccountChange}
          value={account}
          error={accountError}
        />
        <TextField
          id="account-url"
          label="Website"
          type="url"
          placeholder="Enter a URL for the website"
          onChange={onUrlChange}
          value={url}
          error={urlError}
        />

        <ViewablePassword
          id="account-password"
          label="Password"
          placeholder="Enter a password"
          value={password}
          onChange={onPasswordChange}
          error={passwordError}
        />
      </Stack>
    </form>
  );
}
