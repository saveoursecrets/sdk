import { WebVault } from "sos-wasm";

export type SecretInfo = [SecretMeta, Secret];

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

export interface VaultWorker {
  WebVault(): Promise<WebVault>;
  generatePassphrase(words: number): Promise<[string, number]>;
}

export interface SecretMeta {
  label: string;
  kind: SecretKind;
}

export interface NewVaultResult {
  label: string;
  password: string;
}

export interface KeyValueError {
  key: boolean;
  value: boolean;
}

export interface Credentials {
  [index: string]: string;
}

export interface UnlockVaultResult {
  password: string;
}

export interface User {
  token?: string;
  address?: string;
}
