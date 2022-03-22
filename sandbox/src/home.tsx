import React, { useState } from 'react';
import { useSelector, useDispatch } from "react-redux";
import { WebVault } from 'sos-wasm';
import { useNavigate } from 'react-router-dom';

import { VaultWorker } from './worker';
import { WorkerContext } from "./worker-provider";
import { vaultsSelector, addVault } from './store/vaults';

import Button from '@mui/material/Button';

interface CreateVaultProps {
  worker: VaultWorker;
}

function CreateVault(props: CreateVaultProps) {
  const {worker} = props;
  const dispatch = useDispatch();
  const navigate = useNavigate();

  const createVault = async () => {
    const label = "My Vault";
    const passphrase = "12345678901234567890123456789012"
    const encoder = new TextEncoder();
    const password = encoder.encode(passphrase);
    const vault: WebVault = await new (worker.WebVault as any)();
    await vault.initialize(label, Array.from(password));
    const uuid = await vault.id();
    const storage = {uuid, vault, label, locked: false};
    dispatch(addVault(storage))
    navigate(`/vault/${uuid}`);
  }

  return <>
    <Button onClick={createVault} variant="contained">Create vault</Button>
  </>;
}

export default function Home() {
  return <>
    <WorkerContext.Consumer>
      {(worker) => {
        return (
          <CreateVault
            worker={worker}
          />
        );
      }}
    </WorkerContext.Consumer>
  </>;
}
