import React, { useEffect, useState } from "react";
import { useSelector } from "react-redux";
import { useParams } from "react-router-dom";

import Typography from "@mui/material/Typography";
import Stack from "@mui/material/Stack";
import Button from "@mui/material/Button";
import Box from "@mui/material/Box";
import Divider from "@mui/material/Divider";

import { vaultsSelector } from "../store/vaults";
import {
  SecretMeta,
  SecretKind,
  SecretKindLabel,
  Secret,
  AccountSecret,
  NoteSecret,
  FileSecret,
  CredentialsSecret,
} from "../types";
import { WorkerStorageProps } from "../props";
import { download, humanFileSize } from "../utils";
import { WorkerContext } from "../worker-provider";

import SecretList from "./secret-list";
import SecretIcon from "./secret-icon";
import VaultHeader from "./vault-header";
import UnlockVault from "./unlock-vault";
import NewSecretDial from "./new-secret-dial";

type SecretProps = {
  secretId: string;
  meta: SecretMeta;
};

function SecretHeader(props: SecretProps) {
  const { meta } = props;
  const label = SecretKindLabel.toString(meta.kind);
  return (
    <Box padding={2} paddingBottom={0}>
      <Typography variant="h4" component="div">
        {meta.label}
      </Typography>
      <Stack direction="row" spacing={1} alignItems="center" marginBottom={2}>
        <SecretIcon kind={meta.kind} />
        <Typography variant="subtitle1" gutterBottom component="div">
          {label}
        </Typography>
      </Stack>
      <Divider />
    </Box>
  );
}

type SecretViewProps = WorkerStorageProps & SecretProps;

type SecretViewProps = {
  meta: SecretMeta;
  secret: Secret;
};

function AccountSecretView(props: SecretViewProps) {
  const secret = props.secret as AccountSecret;
  console.log(secret);
}

function NoteSecretView(props: SecretViewProps) {
  const secret = props.secret as NoteSecret;
  return (
    <Box padding={2}>
      <Typography variant="paragraph" component="div">
        {secret.Text}
      </Typography>
    </Box>
  );
}

function FileSecretView(props: SecretViewProps) {
  const { meta } = props;
  const secret = props.secret as FileSecret;
  console.log(secret);

  const mime = secret.Blob.mime || "application/octet-stream";
  const { buffer } = secret.Blob;
  const onOpenFile = (e: React.MouseEvent<HTMLElement>) => {
    e.preventDefault();
    download(meta.label, new Uint8Array(buffer), mime);
  };

  return (
    <Box padding={2}>
      <Stack marginBottom={2}>
        <Typography variant="paragraph" component="div">
          Type: {mime}
        </Typography>
        <Typography variant="paragraph" component="div">
          Size: {humanFileSize(buffer.length)}
        </Typography>
      </Stack>
      <Stack alignItems="center">
        <Button onClick={onOpenFile}>Open this file in the browser</Button>
      </Stack>
    </Box>
  );
}

function CredentialsSecretView(props: SecretViewProps) {
  const secret = props.secret as CredentialsSecret;
  console.log(secret);
}

function SecretView(props: SecretViewProps) {
  const { storage, secretId } = props;
  const [secretData, setSecretData] = useState(null);

  useEffect(() => {
    const loadSecret = async () => {
      const { vault } = storage;
      const result = await vault.getSecret(secretId);
      setSecretData(result);
    };
    loadSecret();
  }, [secretId]);

  if (!secretData) {
    return null;
  }

  const [meta, secret] = secretData;
  const label = SecretKindLabel.toString(meta.kind);

  switch (meta.kind) {
    case SecretKind.Account:
      return <AccountSecretView meta={meta} secret={secret} />;
    case SecretKind.Note:
      return <NoteSecretView meta={meta} secret={secret} />;
    case SecretKind.Credentials:
      return <CredentialsSecretView meta={meta} secret={secret} />;
    case SecretKind.File:
      return <FileSecretView meta={meta} secret={secret} />;
  }
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
      <VaultHeader storage={storage} worker={worker} />
      <Stack direction="row">
        <SecretList worker={worker} storage={storage} uuid={secretId} />
        <Box flex={1}>
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
