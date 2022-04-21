import { WebVault, WebSigner, Signup } from "sos-wasm";

export type Account = {
  signer?: WebSigner;
  address?: string;
  vaults?: Summary[];
};

export type Summary = {
  version: number;
  id: string;
  name: string;
}

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

