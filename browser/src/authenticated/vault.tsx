import React from "react";
import { useSelector } from "react-redux";
import { useParams } from "react-router-dom";

import { WorkerStorageProps } from "../props";

import { vaultsSelector } from "../store/vaults";

import { WorkerContext } from "../worker-provider";
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

export default function Vault() {
  const params = useParams();
  const { vaultId } = params;
  const { vaults } = useSelector(vaultsSelector);

  const storage = vaults.find((v) => v.uuid === vaultId);

  if (!storage) {
    return <p>Vault not found</p>;
  }

  return (
    <>
      <WorkerContext.Consumer>
        {(worker) => {
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
