import React from 'react';
import {useSelector, useDispatch} from 'react-redux';
import {useNavigate} from 'react-router-dom';

import {VaultWorker, WebVault} from './worker';
import {dialogsSelector, setDialogVisible, NEW_VAULT} from './store/dialogs';
import {createVault} from './store/vaults';
import NewVaultDialog from './new-vault-dialog';
import {NewVaultResult} from './types';

interface DialogProps {
  worker: VaultWorker;
}

export default function Dialogs(props: DialogProps) {
  const {worker} = props;
  const navigate = useNavigate();
  const dispatch = useDispatch();
  const {dialogs} = useSelector(dialogsSelector);

  //console.log("DIALOGS RENDERING", dialogs);

  const createNewVault = async (result: NewVaultResult) => {
    cancelDialog(NEW_VAULT);
    dispatch(createVault({worker, navigate, result}))
  };

  const cancelDialog = (key: string) => {
    dispatch(setDialogVisible([key, false]))
  }

  return <>
      <NewVaultDialog
        open={dialogs[NEW_VAULT] || false}
        handleCancel={() => cancelDialog(NEW_VAULT)}
        handleOk={createNewVault}
      />
  </>;
}
