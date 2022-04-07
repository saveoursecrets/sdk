import React, { useState } from "react";
import { useSelector, useDispatch } from "react-redux";
import { useParams } from "react-router-dom";

import { vaultsSelector } from "../store/vaults";
import { SecretMeta } from "../types";
import { WorkerContext } from "../worker-provider";

import SecretList from "./secret-list";
import VaultHeader from "./vault-header";
import NewSecretDial from "./new-secret-dial";

import Typography from "@mui/material/Typography";
import Stack from "@mui/material/Stack";
import Box from "@mui/material/Box";

type SecretHeaderProps = {
  label: string;
  meta: SecretMeta;
};

function SecretHeader(props: SecretHeaderProps) {
  const { label } = props;
  return (
    <>
      <Typography variant="h3" gutterBottom component="div">
        {label}
      </Typography>
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
    return <p>Vault is locked</p>
  }
  */

  const { meta } = storage;

  const secret = [...Object.entries(meta)].find((v) => {
    const [label, [uuid]] = v;
    return uuid === secretId;
  });

  if (!secret) {
    return <p>Secret not found</p>;
  }

  const [label, [uuid, metaData]] = secret;

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
                  <SecretHeader label={label} meta={metaData} />
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
