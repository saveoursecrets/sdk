import React from "react";
import { useSelector, useDispatch } from "react-redux";
import { useNavigate } from "react-router-dom";

import { VaultWorker, WebVault } from "../../worker";
import { dialogsSelector, setDialogVisible, NEW_VAULT, NEW_SECURE_NOTE } from "../../store/dialogs";
import { vaultsSelector, createNewVault as dispatchNewVault, createNewSecureNote as dispatchNewSecureNote } from "../../store/vaults";
import { NewVaultResult, SecureNoteResult } from "../../types";

import NewVaultDialog from "./new-vault";
import SecureNoteDialog from "./secure-note";

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
    dispatch(dispatchNewSecureNote({ worker, result, owner: current }));
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
    </>
  );
}
