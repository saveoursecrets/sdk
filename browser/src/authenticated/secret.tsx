import React, { useEffect, useState } from "react";
import { useSelector, useDispatch } from "react-redux";
import { useParams, useSearchParams } from "react-router-dom";

import Typography from "@mui/material/Typography";
import Paper from "@mui/material/Paper";
import Stack from "@mui/material/Stack";
import Link from "@mui/material/Link";
import Button from "@mui/material/Button";
import Box from "@mui/material/Box";
import Divider from "@mui/material/Divider";

import IconButton from "@mui/material/IconButton";
import Menu from "@mui/material/Menu";
import MenuItem from "@mui/material/MenuItem";

import MoreVertIcon from "@mui/icons-material/MoreVert";

import { vaultsSelector } from "../store/vaults";

import {
  NEW_SECURE_NOTE,
  CONFIRM_DELETE_SECRET,
  setDialogVisible,
} from "../store/dialogs";

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
import { WorkerStorageProps, StorageProps } from "../props";
import { download, humanFileSize } from "../utils";
import { WorkerContext } from "../worker-provider";

import SecretList from "./secret-list";
import VaultHeader from "./vault-header";
import UnlockVault from "./unlock-vault";
import NewSecretDial from "./new-secret-dial";
import ReadOnlyPassword from "./forms/readonly-password";

type SecretMetaProps = {
  meta: SecretMeta;
};

type SecretHeaderProps = {
  secretId: string;
  secret: Secret;
} & SecretMetaProps;

function SecretHeader(props: SecretHeaderProps) {
  const { secretId, meta, secret } = props;
  const dispatch = useDispatch();
  const label = SecretKindLabel.toString(meta.kind);

  const [menuAnchor, setMenuAnchor] = useState(null);
  const open = Boolean(menuAnchor);

  const showMenu = (event: React.MouseEvent<HTMLElement>) => {
    setMenuAnchor(event.currentTarget);
  };

  const onEdit = (event: React.MouseEvent<HTMLElement>) => {
    console.log("Edit item", secretId, meta.kind, SecretKind.Note);
    switch (meta.kind) {
      case SecretKind.Note:
        console.log("edit a note!");
        dispatch(
          setDialogVisible([NEW_SECURE_NOTE, true, { secretId, meta, secret }])
        );
        break;
      default:
        console.error("TODO: edit other note types");
    }

    closeMenu();
  };

  const onDelete = (event: React.MouseEvent<HTMLElement>) => {
    const { label } = meta;
    dispatch(
      setDialogVisible([CONFIRM_DELETE_SECRET, true, { label, secretId }])
    );
    closeMenu();
  };

  const closeMenu = () => {
    setMenuAnchor(null);
  };

  const ITEM_HEIGHT = 48;

  return (
    <Stack direction="row" spacing={2} marginBottom={1}>
      <Stack flex={1}>
        <Typography variant="body2" component="div">
          {meta.label}
        </Typography>
        <Typography
          variant="caption"
          gutterBottom
          component="div"
          color="text.secondary"
        >
          {label}
        </Typography>
      </Stack>

      <IconButton
        sx={{ width: 40, height: 40 }}
        aria-label="more actions"
        id="actions-button"
        aria-controls={open ? "actions-menu" : undefined}
        aria-expanded={open ? "true" : undefined}
        aria-haspopup="true"
        onClick={showMenu}
      >
        <MoreVertIcon />
      </IconButton>

      <Menu
        id="actions-menu"
        MenuListProps={{
          "aria-labelledby": "actions-button",
        }}
        anchorEl={menuAnchor}
        open={open}
        onClose={closeMenu}
        PaperProps={{
          style: {
            maxHeight: ITEM_HEIGHT * 4.5,
            width: "20ch",
          },
        }}
      >
        <MenuItem onClick={onEdit}>Edit</MenuItem>
        <MenuItem onClick={onDelete}>Delete</MenuItem>
      </Menu>
    </Stack>
  );
}

type SecretItemProps = {
  meta: SecretMeta;
  secret: Secret;
};

function AccountSecretView(props: SecretItemProps) {
  const secret = props.secret as AccountSecret;
  const { account, url, password } = secret;

  return (
    <Stack spacing={2}>
      <Typography variant="subtitle1" component="div">
        {account}
      </Typography>
      {url ? (
        <Link href={url} underline="hover">
          {url}
        </Link>
      ) : null}
      <ReadOnlyPassword value={password} compact={false} />
    </Stack>
  );
}

function NoteSecretView(props: SecretItemProps) {
  const secret = props.secret as NoteSecret;
  return (
    <Box paddingTop={1}>
      <Typography variant="body1" component="div">
        {secret}
      </Typography>
    </Box>
  );
}

function FileSecretView(props: SecretItemProps) {
  const { meta } = props;
  const secret = props.secret as FileSecret;

  const mime = secret.mime || "application/octet-stream";
  const { buffer } = secret;
  const onOpenFile = (e: React.MouseEvent<HTMLElement>) => {
    e.preventDefault();
    download(meta.label, new Uint8Array(buffer), mime);
  };

  return (
    <>
      <Stack marginBottom={2}>
        <Typography variant="body1" component="div">
          Type: {mime}
        </Typography>
        <Typography variant="body1" component="div">
          Size: {humanFileSize(buffer.length)}
        </Typography>
      </Stack>
      <Stack alignItems="center">
        <Button onClick={onOpenFile}>Open this file in the browser</Button>
      </Stack>
    </>
  );
}

function CredentialsSecretView(props: SecretItemProps) {
  const secret = props.secret as CredentialsSecret;

  const credentials = new Map(Object.entries(secret));
  // Sort for deterministic ordering
  const list = [...credentials.entries()].sort(
    (a: [string, string], b: [string, string]) => {
      const [ka] = a;
      const [kb] = b;
      if (ka < kb) {
        return -1;
      }
      if (ka > kb) {
        return 1;
      }
      return 0;
    }
  );

  return (
    <>
      {list.map((item: [string, string], index: number) => {
        const [name, value] = item;
        return (
          <Stack
            key={index}
            direction="row"
            paddingBottom={1}
            alignItems="center"
          >
            <Typography variant="body1" component="div" flex={1}>
              {name}
            </Typography>
            <ReadOnlyPassword value={value} compact={true} />
          </Stack>
        );
      })}
    </>
  );
}

type SecretLayoutProps = SecretHeaderProps & { children?: React.ReactNode };

function SecretLayout(props: SecretLayoutProps) {
  const { secretId, meta, secret } = props;
  return (
    <Box padding={2}>
      <Paper variant="outlined">
        <Box padding={2}>
          <SecretHeader secretId={secretId} meta={meta} secret={secret} />
          <Divider />
          <Box marginTop={1}>{props.children}</Box>
        </Box>
      </Paper>
    </Box>
  );
}

type SecretViewProps = {
  secretId: string;
} & WorkerStorageProps;

function SecretView(props: SecretViewProps) {
  const { storage, secretId } = props;
  const [secretData, setSecretData] = useState(null);
  const [searchParams, setSearchParams] = useSearchParams();

  useEffect(() => {
    const loadSecret = async () => {
      const { vault } = storage;
      const result = await vault.read(secretId);
      setSecretData(result);
    };
    loadSecret();
  }, [secretId, searchParams]);

  if (!secretData) {
    return null;
  }

  const [meta, secret] = secretData;
  const label = SecretKindLabel.toString(meta.kind);

  switch (meta.kind) {
    case SecretKind.Account:
      return (
        <SecretLayout secretId={secretId} meta={meta} secret={secret}>
          <AccountSecretView meta={meta} secret={secret} />
        </SecretLayout>
      );
    case SecretKind.Note:
      return (
        <SecretLayout secretId={secretId} meta={meta} secret={secret}>
          <NoteSecretView meta={meta} secret={secret} />
        </SecretLayout>
      );
    case SecretKind.Credentials:
      return (
        <SecretLayout secretId={secretId} meta={meta} secret={secret}>
          <CredentialsSecretView meta={meta} secret={secret} />
        </SecretLayout>
      );
    case SecretKind.File:
      return (
        <SecretLayout secretId={secretId} meta={meta} secret={secret}>
          <FileSecretView meta={meta} secret={secret} />
        </SecretLayout>
      );
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
        <SecretList
          maxWidth={320}
          worker={worker}
          storage={storage}
          uuid={secretId}
        />
        <Box flex={1}>
          <SecretView storage={storage} worker={worker} secretId={secretId} />
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
