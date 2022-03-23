import React, { useEffect, useState } from 'react';
import { useSelector, useDispatch } from "react-redux";
import { WebVault } from 'sos-wasm';
import { useNavigate, useParams } from 'react-router-dom';

import Typography from '@mui/material/Typography';
import Link from '@mui/material/Link';
import Divider from '@mui/material/Divider';

import { VaultWorker } from './worker';
import { WorkerContext } from "./worker-provider";
import { vaultsSelector, VaultStorage } from './store/vaults';
import SecretList from "./secret-list";

function downloadVault(fileName: string, buffer: Uint8Array) {
    const blob = new Blob([buffer], {type: "application/octet-stream"});
    const link = document.createElement('a');
    link.href = window.URL.createObjectURL(blob);
    link.download = fileName;
    link.click();
}

interface VaultViewProps {
  worker: VaultWorker;
  storage: VaultStorage;
}

function VaultView(props: VaultViewProps) {
  const { worker, storage } = props;
  const { vault, uuid, label } = storage;
  const [secrets, setSecrets] = useState(null);

  const download = async (
      e: React.MouseEvent<HTMLElement>
  ) => {
    e.preventDefault();
    const buffer = await vault.buffer();
    downloadVault(`${uuid}.vault`, buffer);
  }

  useEffect(() => {
    const getSecretsMeta = async () => {
      const secrets = await vault.getSecretIndex();
      const secretsMap = new Map(Object.entries(secrets));
      console.log("loaded secrets", secretsMap);
      setSecrets(() => secretsMap);
    }
    getSecretsMeta();
  }, [storage]);

  return <>
    <Typography variant="h3" gutterBottom component="div">
        {label}
    </Typography>
    <Typography variant="h6" gutterBottom component="div">
        {uuid}
    </Typography>
    <Link href="#" onClick={(e) => download(e)}>Download</Link>
    <Divider />
    <SecretList worker={worker} secrets={secrets} />
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
