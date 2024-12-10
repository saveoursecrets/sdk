export type TupleOfTwo<T, U> = [T, U];
export type TupleOfThree<T, U, V> = [T, U, V];
export type AccountsList = PublicIdentity[];
export type DocumentsList = Document[];
export type SecretPath = TupleOfTwo<string, string>;
export type HashSet<T> = Set<T>;
export type Uri = string;
export type Method = string;
export type VaultId = string;
export type VaultFlags = number;
export type SecretId = string;
export type Cipher = string;
export type KeyDerivation = string;
export type SecretBox<T> = T;
export type Set<T> = T[];
export type SecretString = SecretBox<string>;
export type Vcard = never;
export type Totp = never;
export type AgeVersion = never;

// Internally this is a HashMap but we can't serialize 
// that to JSON so for Javascript it's just an array
export type Headers = [string, string[]][];
// Backwards compatible aliases
export type AccountState = PublicIdentity;

export type FolderInfo = Summary;
export interface FoldersList {
  [accountId: string]: FolderInfo[];
}
export interface SearchResults {
  [accountId: string]: DocumentsList;
}

export interface AuthenticatedList{
  [accountId: string]: boolean;
}

export enum Kind {
  Individual = "individual",
  Group = "group",
  Org = "org",
  Location = "location",
}

export type EmbeddedFileContent = {
    name: string,
    mime: string,
    buffer: number[],
    checksum: never,
}

export type ExternalFileContent = {
  name: String;
  mime: String;
  checksum: never;
  size: number;
  path?: string;
}

export type FileContent = EmbeddedFileContent | ExternalFileContent;

// Define secret enum variants manually as we 
// want to use untagged enum representation which 
// is not supported by typesafe

export type NoteSecret = {
  text: string;
  userData: UserData;
}

export type FileSecret = {
  content: FileContent;
  userData: UserData;
}

export type LoginSecret = {
  account: string;
  password: string;
  url: string[];
  userData: UserData;
}

export type ListItems = {
  [key: string]: string;
};

export type ListSecret = {
  items: ListItems;
  userData: UserData;
}

export type PemSecret = {
  certificates: string[];
  userData: UserData;
}

export type PageSecret = {
  title: string;
  mime: string;
  document: string;
  userData: UserData;
}

export type SignerSecret = {
  privateKey: string;
  userData: UserData;
}

export type ContactSecret = {
  vcard: Vcard;
  userData: UserData;
}

export type TotpSecret = {
  totp: Totp;
  userData: UserData;
}

export type CardSecret = {
  number: string;
  cvv: string;
  name?: string;
  expiry?: string;
  atmPin?: string;
  userData: UserData;
}

export type BankSecret = {
  number?: string;
  routing?: string;
  iban?: string;
  bic?: string;
  swift?: string;
  userData: UserData;
}

export type LinkSecret = {
  url: string;
  label?: string;
  title?: string;
  userData: UserData;
}

export type PasswordSecret = {
  password: string;
  name?: string;
  userData: UserData;
}

export type IdentitySecret = {
  idKind: IdentityKind;
  number: string;
  issuePlace?: string;
  issueDate?: string;
  expiryDate?: string;
  userData: UserData;
}

export type AgeSecret = {
  ageVersion: AgeVersion;
  key: string;
  userData: UserData;
}

export type Secret = NoteSecret | FileSecret | LoginSecret | ListSecret | PemSecret | PageSecret | SignerSecret | ContactSecret | TotpSecret | CardSecret | BankSecret | LinkSecret | PasswordSecret | IdentitySecret | AgeSecret;
