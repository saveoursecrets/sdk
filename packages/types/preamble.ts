export type TupleOfTwo<T, U> = [T, U];
export type AccountState = TupleOfTwo<PublicIdentity, boolean>;
export type AccountsList = AccountState[];
export type DocumentsList = Document[];
export type SearchResults = TupleOfTwo<PublicIdentity, DocumentsList>;
export type HashSet<T> = Set<T>;
