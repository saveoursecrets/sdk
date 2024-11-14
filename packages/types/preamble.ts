export type TupleOfTwo<T, U> = [T, U];
export type AccountState = TupleOfTwo<PublicIdentity, boolean>;
export type AccountsList = AccountState[];
export type DocumentsList = Document[];
export type SearchResultEntry = TupleOfTwo<PublicIdentity, DocumentsList>;
export type SearchResults = SearchResultEntry[];
export type SecretPath = TupleOfTwo<string, string>;
export type HashSet<T> = Set<T>;
