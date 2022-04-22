import React, { useEffect } from "react";
import { useSelector, useDispatch } from "react-redux";
import { useParams } from "react-router-dom";

import { Stack, Typography, CircularProgress } from "@mui/material";

import { WorkerProps, WorkerStorageProps } from "../props";
import { Summary } from "../types";

import { loadVault, vaultsSelector } from "../store/vaults";
import { accountSelector } from "../store/account";
import { WorkerContext } from "../worker-provider";

import NotFound from "../not-found";
import SecretList from "./secret-list";
import NewSecretDial from "./new-secret-dial";
import VaultHeader from "./vault-header";
import UnlockVault from "./unlock-vault";

function VaultLocked(props: WorkerStorageProps) {
  const { worker, storage } = props;
  return (
    <>
      <VaultHeader worker={worker} storage={storage} />
      <UnlockVault worker={worker} storage={storage} />
    </>
  );
}

function VaultUnlocked(props: WorkerStorageProps) {
  const { worker, storage } = props;
  return (
    <>
      <VaultHeader worker={worker} storage={storage} />
      <SecretList worker={worker} storage={storage} />
      <NewSecretDial />
    </>
  );
}

type VaultLoaderProps = {
  summary: Summary;
} & WorkerProps;

function VaultLoader(props: VaultLoaderProps) {
  const dispatch = useDispatch();
  const { account } = useSelector(accountSelector);
  const { summary, worker } = props;

  useEffect(() => {
    const onLoadVault = () => {
      dispatch(loadVault({ summary, worker, account }));
    };
    onLoadVault();
  }, [summary]);

  return (
    <Stack alignItems="center" padding={3}>
      <Stack direction="row" spacing={2}>
        <CircularProgress size={20} />
        <Typography variant="body2">Loading {summary.name} vault...</Typography>
      </Stack>
    </Stack>
  );
}

export default function Vault() {
  const params = useParams();
  const { vaultId } = params;
  const { account } = useSelector(accountSelector);
  const { vaults } = useSelector(vaultsSelector);

  const { summaries } = account;

  const summary = summaries.find((v) => v.id === vaultId);

  if (!summary) {
    return <NotFound />;
  }

  const storage = vaults.find((v) => v.uuid === vaultId);

  return (
    <>
      <WorkerContext.Consumer>
        {(worker) => {
          if (!storage) {
            return <VaultLoader summary={summary} worker={worker} />;
          }

          return storage.locked ? (
            <VaultLocked worker={worker} storage={storage} />
          ) : (
            <VaultUnlocked worker={worker} storage={storage} />
          );
        }}
      </WorkerContext.Consumer>
    </>
  );
}
