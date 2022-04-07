import { WebVault } from "sos-wasm";

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

export interface AccountPasswordResult {
  label: string;
  account: string;
  url: string;
  password: string;
}

export interface SecureNoteResult {
  label: string;
  note: string;
}

export interface KeyValueError {
  key: boolean;
  value: boolean;
}

export interface Credentials {
  [index: string]: string;
}

export interface CredentialsResult {
  label: string;
  credentials: Credentials;
}

export interface FileUploadResult {
  label: string;
  name?: string;
  buffer?: number[];
}

export interface UnlockVaultResult {
  password: string;
}

export interface User {
  token?: string;
  address?: string;
}
