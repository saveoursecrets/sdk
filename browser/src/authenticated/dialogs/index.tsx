import React from "react";
import { useSelector, useDispatch } from "react-redux";
import { useNavigate } from "react-router-dom";

import {
  dialogsSelector,
  setDialogVisible,
  NEW_VAULT,
  NEW_SECURE_NOTE,
  NEW_ACCOUNT_PASSWORD,
  NEW_CREDENTIALS,
  NEW_FILE_UPLOAD,
} from "../../store/dialogs";
import {
  vaultsSelector,
  createNewVault as dispatchNewVault,
  createNewSecureNote as dispatchNewSecureNote,
  createNewAccountPassword as dispatchNewAccountPassword,
  createNewCredentials as dispatchNewCredentials,
  createNewFileUpload as dispatchNewFileUpload,
} from "../../store/vaults";
import {
  NewVaultResult,
  SecureNoteResult,
  AccountPasswordResult,
  CredentialsResult,
  FileUploadResult,
  VaultWorker,
} from "../../types";

import NewVaultDialog from "./new-vault";
import SecureNoteDialog from "./secure-note";
import AccountPasswordDialog from "./account-password";
import CredentialsDialog from "./credentials";
import FileUploadDialog from "./file-upload";

interface DialogProps {
  worker: VaultWorker;
}

export default function Dialogs(props: DialogProps) {
  const { worker } = props;
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const { dialogs } = useSelector(dialogsSelector);
  const { current } = useSelector(vaultsSelector);

  //console.log("Render dialog with current", current);

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

  const createNewFileUpload = async (result: FileUploadResult) => {
    console.log(result);
    cancelDialog(NEW_FILE_UPLOAD);
    dispatch(dispatchNewFileUpload({ result, owner: current }));
  };

  const cancelDialog = (key: string) => {
    dispatch(setDialogVisible([key, false]));
  };

  return (
    <>
      <NewVaultDialog
        worker={worker}
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

      <FileUploadDialog
        open={dialogs[NEW_FILE_UPLOAD] || false}
        handleCancel={() => cancelDialog(NEW_FILE_UPLOAD)}
        handleOk={createNewFileUpload}
      />
    </>
  );
}
