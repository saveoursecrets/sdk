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

export interface SecretMeta {
  label: string;
}

export interface SearchMeta {
  meta: SecretMeta;
  kind: SecretKind;
}

export interface SecureNoteResult {
  label: string;
  note: string;
}

export interface NewVaultResult {
  label: string;
  password: string;
}

export interface UnlockVaultResult {
  password: string;
}
