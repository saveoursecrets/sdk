export enum SecretKind {
  Account = 1,
  Note = 2,
  Credentials = 3,
  File = 4,
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
