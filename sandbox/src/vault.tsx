import React from 'react';
import { useSelector, useDispatch } from "react-redux";
import { WebVault } from 'sos-wasm';
import { useNavigate, useParams } from 'react-router-dom';

import Typography from '@mui/material/Typography';

import { VaultWorker } from './worker';
import { WorkerContext } from "./worker-provider";
import { vaultsSelector, VaultStorage } from './store/vaults';

interface VaultViewProps {
  worker: VaultWorker;
  storage: VaultStorage;
}

function VaultView(props: VaultViewProps) {
  const {storage} = props;
  const { vault, uuid, label } = storage;
  return <>
    <Typography variant="h3" gutterBottom component="div">
        {label}
    </Typography>
    <Typography variant="h6" gutterBottom component="div">
        {uuid}
    </Typography>
  </>;
}

export default function Vault() {
  const params = useParams();
  const { id } = params;
  const { vaults } = useSelector(vaultsSelector);

  const storage = vaults.find((v) => v.uuid === id);

  if (!storage) {
    return <p>Vault not found</p>;
  }

  return <>
    <WorkerContext.Consumer>
      {(worker) => {
        return (
          <VaultView worker={worker} storage={storage} />
        );
      }}
    </WorkerContext.Consumer>
  </>;
}
