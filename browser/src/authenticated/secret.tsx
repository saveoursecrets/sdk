import React from "react";
import { useSelector } from "react-redux";
import { useParams } from "react-router-dom";

import Typography from "@mui/material/Typography";
import Stack from "@mui/material/Stack";
import Box from "@mui/material/Box";

import { vaultsSelector } from "../store/vaults";
import { SecretMeta } from "../types";
import { WorkerStorageProps } from "../props";
import { WorkerContext } from "../worker-provider";

import SecretList from "./secret-list";
import VaultHeader from "./vault-header";
import UnlockVault from "./unlock-vault";
import NewSecretDial from "./new-secret-dial";

type SecretProps = {
  secretId: string;
  meta: SecretMeta;
};

function SecretHeader(props: SecretProps) {
  const { meta } = props;
  return (
    <>
      <Typography variant="h3" gutterBottom component="div">
        {meta.label}
      </Typography>
    </>
  );
}

type SecretViewProps = WorkerStorageProps & SecretProps;

function SecretView(props: SecretViewProps) {
  return (
    <>
      <p>{props.secretId}</p>
    </>
  );
}

function SecretLocked(props: WorkerStorageProps) {
  const { worker, storage } = props;
  return (
    <>
      <VaultHeader worker={worker} storage={storage} />
      <UnlockVault worker={worker} storage={storage} />
    </>
  );
}

type SecretUnlockedProps = {
  secretId: string;
  meta: SecretMeta;
} & WorkerStorageProps;

function SecretUnlocked(props: SecretUnlockedProps) {
  const { worker, storage, secretId, meta } = props;
  return (
    <>
      <WorkerContext.Consumer>
        {(worker) => {
          return (
            <>
              <VaultHeader storage={storage} worker={worker} />
              <Stack direction="row">
                <SecretList worker={worker} storage={storage} uuid={secretId} />
                <Box padding={2}>
                  <SecretHeader secretId={secretId} meta={meta} />
                  <SecretView
                    storage={storage}
                    worker={worker}
                    secretId={secretId}
                    meta={meta}
                  />
                </Box>
              </Stack>
              <NewSecretDial />
            </>
          );
        }}
      </WorkerContext.Consumer>
    </>
  );
}

export default function Secret() {
  const params = useParams();
  const { vaultId, secretId } = params;
  const { vaults } = useSelector(vaultsSelector);
  const storage = vaults.find((v) => v.uuid === vaultId);

  if (!storage) {
    return <p>Vault not found</p>;
  }

  /*
  if (storage.locked) {
    // TODO: show unlock form!
    return <p>Vault is locked</p>
  }
  */

  const { meta } = storage;

  const secret = [...Object.entries(meta)].find((v) => {
    const [, [uuid]] = v;
    return uuid === secretId;
  });

  if (!secret) {
    return <p>Secret not found</p>;
  }

  const [, [, metaData]] = secret;

  return (
    <>
      <WorkerContext.Consumer>
        {(worker) => {
          return storage.locked ? (
            <SecretLocked worker={worker} storage={storage} />
          ) : (
            <SecretUnlocked
              secretId={secretId}
              meta={metaData}
              worker={worker}
              storage={storage}
            />
          );
        }}
      </WorkerContext.Consumer>
    </>
  );
}
