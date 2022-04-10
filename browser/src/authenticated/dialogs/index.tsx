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
  CONFIRM_DELETE_SECRET,
} from "../../store/dialogs";
import {
  vaultsSelector,
  createNewVault as dispatchNewVault,
  createNewSecret as dispatchNewSecret,
  deleteSecret as dispatchDeleteSecret,
} from "../../store/vaults";
import {
  NewVaultResult,
  VaultWorker,
  SecretInfo,
  SecretReference,
} from "../../types";

import NewVaultDialog from "./new-vault";
import SecureNoteDialog from "./secure-note";
import AccountPasswordDialog from "./account-password";
import CredentialsDialog from "./credentials";
import FileUploadDialog from "./file-upload";
import ConfirmDeleteSecretDialog from "./confirm-delete-secret";

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

  const createNewSecureNote = async (result: SecretInfo) => {
    cancelDialog(NEW_SECURE_NOTE);
    dispatch(dispatchNewSecret({ result, owner: current }));
  };

  const createNewAccountPassword = async (result: SecretInfo) => {
    cancelDialog(NEW_ACCOUNT_PASSWORD);
    dispatch(dispatchNewSecret({ result, owner: current }));
  };

  const createNewCredentials = async (result: SecretInfo) => {
    cancelDialog(NEW_CREDENTIALS);
    dispatch(dispatchNewSecret({ result, owner: current }));
  };

  const createNewFileUpload = async (result: SecretInfo) => {
    cancelDialog(NEW_FILE_UPLOAD);
    dispatch(dispatchNewSecret({ result, owner: current }));
  };

  const deleteSecret = async (result: string) => {
    cancelDialog(CONFIRM_DELETE_SECRET);
    await dispatch(dispatchDeleteSecret({ result, navigate, owner: current }));
  };

  const cancelDialog = (key: string) => {
    dispatch(setDialogVisible([key, false, null]));
  };

  return (
    <>
      <NewVaultDialog
        worker={worker}
        open={dialogs[NEW_VAULT][0] || false}
        handleCancel={() => cancelDialog(NEW_VAULT)}
        handleOk={createNewVault}
      />

      <SecureNoteDialog
        open={dialogs[NEW_SECURE_NOTE][0] || false}
        handleCancel={() => cancelDialog(NEW_SECURE_NOTE)}
        handleOk={createNewSecureNote}
      />

      <AccountPasswordDialog
        open={dialogs[NEW_ACCOUNT_PASSWORD][0] || false}
        handleCancel={() => cancelDialog(NEW_ACCOUNT_PASSWORD)}
        handleOk={createNewAccountPassword}
      />

      <CredentialsDialog
        open={dialogs[NEW_CREDENTIALS][0] || false}
        handleCancel={() => cancelDialog(NEW_CREDENTIALS)}
        handleOk={createNewCredentials}
      />

      <FileUploadDialog
        open={dialogs[NEW_FILE_UPLOAD][0] || false}
        handleCancel={() => cancelDialog(NEW_FILE_UPLOAD)}
        handleOk={createNewFileUpload}
      />

      <ConfirmDeleteSecretDialog
        open={dialogs[CONFIRM_DELETE_SECRET][0] || false}
        handleCancel={() => cancelDialog(CONFIRM_DELETE_SECRET)}
        handleOk={deleteSecret}
        secret={dialogs[CONFIRM_DELETE_SECRET][1] as SecretReference}
      />
    </>
  );
}
