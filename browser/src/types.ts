import { WebVault, WebSigner, Signup } from "sos-wasm";

// Operation that triggered a conflict response.
export enum ConflictOperation {
  CREATE_SECRET = 1,
  READ_SECRET,
  UPDATE_SECRET,
  DELETE_SECRET,
}

export type ChangeSequencePair = {
  local: number;
  remote: number;
};

// Intermediary state containing conflict information.
export type Conflict = {
  operation: ConflictOperation;
  changePair: ChangeSequencePair;
  vaultId: string;
  secretId: string;
};

// Functions to handle attempts to resolve conflicts.
export type ConflictHandlers = {
  // Pull the remote vault.
  pull: () => Promise<unknown>;
  // Push local vault to the remote server.
  push: () => Promise<unknown>;
  // Replay the last operation that got a conflict response.
  replay: () => Promise<unknown>;
};

export type Nonce = {
  Nonce12?: number[];
  Nonce24?: number[];
};

export type AeadPack = {
  nonce: Nonce;
  ciphertext: number[];
};

export type Payload = {
  CreateSecret: [number, string, [AeadPack, AeadPack]];
  ReadSecret: [number, string];
  UpdateSecret: [number, string, [AeadPack, AeadPack]];
  DeleteSecret: [number, string];
};

export type Account = {
  signer?: WebSigner;
  address?: string;
  summaries?: Summary[];
};

export type Summary = {
  version: number;
  id: string;
  name: string;
};

export type Signature = {
  r: string;
  s: string;
  v: number;
};

export type SecretData = {
  secretId?: string;
  meta: SecretMeta;
  secret: Secret;
};

export type AccountSecret = {
  account: string;
  url?: string;
  password: string;
};

export type NoteSecret = string;

export type FileSecret = {
  buffer: number[];
  mime?: string;
};

export type CredentialsSecret = {
  [index: string]: string;
};

export type Secret =
  | AccountSecret
  | NoteSecret
  | FileSecret
  | CredentialsSecret;

export enum SecretKind {
  // secret::kind::ACCOUNT
  Account = 1,
  // secret::kind::TEXT
  Note = 2,
  // secret::kind::CREDENTIALS
  Credentials = 3,
  // secret::kind::BLOB
  File = 4,
}

export class SecretKindLabel {
  public static toString(kind: SecretKind) {
    switch (kind) {
      case SecretKind.Account:
        return "Account";
      case SecretKind.Note:
        return "Note";
      case SecretKind.Credentials:
        return "Credentials";
      case SecretKind.File:
        return "File";
    }
  }
}

export type VaultWorker = {
  WebVault(): Promise<WebVault>;
  Signup(): Promise<Signup>;
  WebSigner(): Promise<WebSigner>;
  generatePassphrase(words: number): Promise<[string, number]>;
};

export type SecretReference = {
  secretId: string;
  label: string;
};

export type SecretMeta = {
  label: string;
  kind: SecretKind;
};

export type NewVaultResult = {
  label: string;
  name: string;
  password: string;
};

export type KeyValueError = {
  key: boolean;
  value: boolean;
};

export type Credentials = {
  [index: string]: string;
};

export type UnlockVaultResult = {
  password: string;
};
