import React from "react";
import { useSelector, useDispatch } from "react-redux";
import { useNavigate } from "react-router-dom";

import { VaultWorker, WebVault } from "../../worker";
import {
  dialogsSelector,
  setDialogVisible,
  NEW_VAULT,
  NEW_SECURE_NOTE,
  NEW_ACCOUNT_PASSWORD,
  NEW_CREDENTIALS,
} from "../../store/dialogs";
import {
  vaultsSelector,
  createNewVault as dispatchNewVault,
  createNewSecureNote as dispatchNewSecureNote,
  createNewAccountPassword as dispatchNewAccountPassword,
  createNewCredentials as dispatchNewCredentials,
} from "../../store/vaults";
import {
  NewVaultResult,
  SecureNoteResult,
  AccountPasswordResult,
  CredentialsResult,
} from "../../types";

import NewVaultDialog from "./new-vault";
import SecureNoteDialog from "./secure-note";
import AccountPasswordDialog from "./account-password";
import CredentialsDialog from "./credentials";

interface DialogProps {
  worker: VaultWorker;
}

export default function Dialogs(props: DialogProps) {
  const { worker } = props;
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const { dialogs } = useSelector(dialogsSelector);
  const { current } = useSelector(vaultsSelector);

  const createNewVault = async (result: NewVaultResult) => {
    cancelDialog(NEW_VAULT);
    dispatch(dispatchNewVault({ worker, navigate, result }));
  };

  const createNewSecureNote = async (result: SecureNoteResult) => {
    cancelDialog(NEW_SECURE_NOTE);
    dispatch(dispatchNewSecureNote({ result, owner: current }));
  };

  const createNewAccountPassword = async (result: AccountPasswordResult) => {
    cancelDialog(NEW_ACCOUNT_PASSWORD);
    dispatch(dispatchNewAccountPassword({ result, owner: current }));
  };

  const createNewCredentials = async (result: CredentialsResult) => {
    console.log(result);
    cancelDialog(NEW_CREDENTIALS);
    dispatch(dispatchNewCredentials({ result, owner: current }));
  };

  const cancelDialog = (key: string) => {
    dispatch(setDialogVisible([key, false]));
  };

  return (
    <>
      <NewVaultDialog
        open={dialogs[NEW_VAULT] || false}
        handleCancel={() => cancelDialog(NEW_VAULT)}
        handleOk={createNewVault}
      />

      <SecureNoteDialog
        open={dialogs[NEW_SECURE_NOTE] || false}
        handleCancel={() => cancelDialog(NEW_SECURE_NOTE)}
        handleOk={createNewSecureNote}
      />

      <AccountPasswordDialog
        open={dialogs[NEW_ACCOUNT_PASSWORD] || false}
        handleCancel={() => cancelDialog(NEW_ACCOUNT_PASSWORD)}
        handleOk={createNewAccountPassword}
      />

      <CredentialsDialog
        open={dialogs[NEW_CREDENTIALS] || false}
        handleCancel={() => cancelDialog(NEW_CREDENTIALS)}
        handleOk={createNewCredentials}
      />
    </>
  );
}
