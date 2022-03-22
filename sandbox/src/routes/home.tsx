import React from "react";
import { useSelector, useDispatch } from "react-redux";
import { WebVault } from 'sos-wasm';

import { VaultWorker } from '../worker';
import { WorkerContext } from "../worker-provider";
import { vaultsSelector, addVault } from '../store/vaults';

import Typography from '@mui/material/Typography';

interface VaultListProps {
  worker: VaultWorker;
}

function VaultList(props: VaultListProps) {
  const { vaults } = useSelector(vaultsSelector);
  return <ul>
    {
      vaults.map((vault) => {
        return <li key={vault.uuid}>{vault.uuid}</li>;
      })
    }
  </ul>;
}

interface CreateVaultProps {
  worker: VaultWorker;
}

function CreateVault(props: CreateVaultProps) {
  const {worker} = props;
  const dispatch = useDispatch();

  const createVault = async () => {
    const label = "My Vault";
    const passphrase = "12345678901234567890123456789012"
    const encoder = new TextEncoder();
    const password = encoder.encode(passphrase);
    const vault: WebVault = await new (worker.WebVault as any)();
    await vault.initialize(label, Array.from(password));
    const uuid = await vault.id();
    const storage = {uuid, vault};
    console.log("create a new vault", storage);
    dispatch(addVault(storage))
  }

  return <button onClick={createVault}>Create vault</button>;
}

export default function Home() {
  //const navigate = useNavigate();
  return <>
    <Typography variant="h2" component="div" gutterBottom>
      Vaults
    </Typography>
    <WorkerContext.Consumer>
      {(worker) => {
        return (
          <div>
            <VaultList
              worker={worker}
            />
            <CreateVault
              worker={worker}
            />
          </div>
        );
      }}
    </WorkerContext.Consumer>
  </>;
}
