import { VaultStorage } from "./store/vaults";
import { VaultWorker } from "./types";

export type WorkerProps = {
  worker: VaultWorker;
};

export type StorageProps = {
  storage: VaultStorage;
};

export type WorkerStorageProps = WorkerProps & StorageProps;
