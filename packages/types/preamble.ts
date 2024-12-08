export type TupleOfTwo<T, U> = [T, U];
export type TupleOfThree<T, U, V> = [T, U, V];
export type AccountsList = PublicIdentity[];
export type DocumentsList = Document[];
export type FoldersList = FolderInfo[];
export type SearchResultEntry = TupleOfTwo<PublicIdentity, DocumentsList>;
export type SearchResults = SearchResultEntry[];
export type SecretPath = TupleOfTwo<string, string>;
export type HashSet<T> = Set<T>;
export type Uri = string;
export type Method = string;
export type VaultId = string;
export type VaultFlags = number;
export type SecretId = string;
export type Cipher = string;
export type KeyDerivation = string;
export type AuthenticatedList = [string, boolean][]

// Internally this is a HashMap but we can't serialize 
// that to JSON so for Javascript it's just an array
export type Headers = [string, string[]][];
// Backwards compatible aliases
export type AccountState = PublicIdentity;
export type FolderInfo = Summary;
