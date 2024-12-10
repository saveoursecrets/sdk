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
export type Pem = string;
export type Vcard = never;
export type SecretSigner = never;
export type AgeVersion = never;
export type TOTP = never;

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

type BodyOf<T extends { kind: string; body: unknown }, K extends T["kind"]> =
  T extends { kind: K } ? T["body"] : never;

type NoteSecret = BodyOf<Secret, "note">;
type FileSecret = BodyOf<Secret, "file">;
type AccountSecret = BodyOf<Secret, "account">;
type ListSecret = BodyOf<Secret, "list">;
type PemSecret = BodyOf<Secret, "pem">;
type PageSecret = BodyOf<Secret, "page">;
type SignerSecret = BodyOf<Secret, "signer">;
type ContactSecret = BodyOf<Secret, "contact">;
type TotpSecret = BodyOf<Secret, "totp">;
type CardSecret = BodyOf<Secret, "card">;
type BankSecret = BodyOf<Secret, "bank">;
type LinkSecret = BodyOf<Secret, "link">;
type PasswordSecret = BodyOf<Secret, "password">;
type IdentitySecret = BodyOf<Secret, "identity">;
type AgeSecret = BodyOf<Secret, "age">;

