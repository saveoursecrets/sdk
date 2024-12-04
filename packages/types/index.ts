export type TupleOfTwo<T, U> = [T, U];
export type TupleOfThree<T, U, V> = [T, U, V];
export type AccountState = TupleOfThree<PublicIdentity, boolean, FoldersList>;
export type AccountsList = AccountState[];
export type DocumentsList = Document[];
export type FoldersList = FolderInfo[];
export type SearchResultEntry = TupleOfTwo<PublicIdentity, DocumentsList>;
export type SearchResults = SearchResultEntry[];
export type SecretPath = TupleOfTwo<string, string>;
export type HashSet<T> = Set<T>;
export type Uri = string;
export type Method = string;
/*
 Generated by typeshare 1.12.0
*/

/** Filter for archived documents. */
export interface ArchiveFilter {
	/** Identifier of the archive vault. */
	id: string;
	/** Whether to include archived documents. */
	includeDocuments: boolean;
}

/** Qualified path to a specific secret in a target account. */
export interface QualifiedPath {
	/** Account address. */
	address: string;
	/** Secret path. */
	secretPath: SecretPath;
}

/** Target for a clipboard copy operation. */
export interface ClipboardTarget {
	/** Qualified path to the secret. */
	path: QualifiedPath;
}

/**
 * Type of secret assigned to the secret meta data.
 * 
 * Matches the enum variants for a secret and is used
 * so we can know the type of secret from the meta data
 * before secret data has been decrypted.
 */
export enum SecretType {
	/** UTF-8 encoded note. */
	Note = "note",
	/** Binary blob. */
	File = "file",
	/** Account with login password. */
	Account = "account",
	/** Collection of credentials as key/value pairs. */
	List = "list",
	/** PEM encoded binary data. */
	Pem = "pem",
	/** UTF-8 text document. */
	Page = "page",
	/** Private signing key. */
	Signer = "signer",
	/** Contact for an organization, person, group or location. */
	Contact = "contact",
	/** Two-factor authentication using a TOTP. */
	Totp = "totp",
	/** Credit or debit card. */
	Card = "card",
	/** Bank account. */
	Bank = "bank",
	/** External link; intended to be used in embedded user fields. */
	Link = "link",
	/** Standalone password; intended to be used in embedded user fields. */
	Password = "password",
	/** Identity secret for passports, driving licenses etc. */
	Identity = "identity",
	/** AGE encryption standard. */
	Age = "age",
}

/** Encapsulates the meta data for a secret. */
export interface SecretMeta {
	/** Kind of the secret. */
	kind: SecretType;
	/** Flags for the secret. */
	flags: number;
	/** Human-friendly label for the secret. */
	label: string;
	/** Collection of tags. */
	tags: HashSet<string>;
	/** Whether this secret is a favorite. */
	favorite: boolean;
	/**
	 * A URN identifier for this secret.
	 * 
	 * This is used when an identity vault stores passphrases
	 * for other vault folders on behalf of a user and can also
	 * be used to assign a predictable identifier for a secret.
	 */
	urn?: string;
	/**
	 * An optional owner identifier.
	 * 
	 * This can be used when creating secrets on behalf of a
	 * third-party plugin or application to indicate the identifier
	 * of the third-party application.
	 */
	ownerId?: string;
	/** Date created timestamp. */
	dateCreated: string;
	/** Last updated timestamp. */
	lastUpdated: string;
}

/**
 * Additional fields that can exposed via search results
 * that are extracted from the secret data but safe to
 * be exposed.
 */
export interface ExtraFields {
	/** Comment about a secret. */
	comment?: string;
	/** Contact type for contact secrets. */
	contactType?: Kind;
	/** Collection of websites. */
	websites?: string[];
}

/** Document that can be indexed. */
export interface Document {
	/** Folder identifier. */
	folderId: string;
	/** Secret identifier. */
	secretId: string;
	/** Secret meta data. */
	meta: SecretMeta;
	/** Extra fields for the document. */
	extra: ExtraFields;
}

/** Information about a folder. */
export interface FolderInfo {
	/** Name of the folder. */
	name: string;
	/** Folder identifier. */
	folderId: string;
}

/** IPC request information. */
export type IpcRequestBody = 
	/**
	 * Probe the native bridge for aliveness.
	 * 
	 * Used to test whether the executable is running
	 * and the native messaging API is connected.
	 */
	| { kind: "probe", body?: undefined }
	/** Query app info. */
	| { kind: "info", body?: undefined }
	/** Query app status. */
	| { kind: "status", body?: undefined }
	/** Ping the server. */
	| { kind: "ping", body?: undefined }
	/** Request to open a URL. */
	| { kind: "openUrl", body: string }
	/** HTTP request routed to the local server. */
	| { kind: "http", body: LocalRequest }
	/** Request the accounts list. */
	| { kind: "listAccounts", body?: undefined }
	/** Request to copy to the clipboard. */
	| { kind: "copy", body: ClipboardTarget }
	/** Request authentication for an account. */
	| { kind: "authenticate", body: {
	/** Account address. */
	address: string;
}}
	/** Request to lock an account. */
	| { kind: "lock", body: {
	/** Account address. */
	address?: string;
}}
	/** Request to search the index. */
	| { kind: "search", body: {
	/** Query needle. */
	needle: string;
	/** Query filter. */
	filter: QueryFilter;
}}
	/** Request to query views in the search index. */
	| { kind: "queryView", body: {
	/** Document views. */
	views: DocumentView[];
	/** Archive filter. */
	archive_filter?: ArchiveFilter;
}};

/** IPC request information. */
export interface IpcRequest {
	/** Request identifier. */
	id: number;
	/** Request payload. */
	payload: IpcRequestBody;
}

/** IPC response error. */
export interface IpcResponseError {
	/** Error code. */
	code: number;
	/** Error message. */
	message: string;
}

/**
 * Request that can be sent to a local data source.
 * 
 * Supports serde so this type is compatible with the
 * browser extension which transfers JSON via the
 * native messaging API.
 * 
 * The body will usually be protobuf-encoded binary data.
 */
export interface LocalRequest {
	/** Request method. */
	method: Method;
	/** Request URL. */
	uri: Uri;
	/** Request headers. */
	headers: Record<string, string[]>;
	/** Request body. */
	body: number[];
}

/**
 * Response received from a local data source.
 * 
 * Supports serde so this type is compatible with the
 * browser extension which transfers JSON via the
 * native messaging API.
 * 
 * The body will usually be protobuf-encoded binary data.
 */
export interface LocalResponse {
	/** Response status code. */
	status: number;
	/** Response headers. */
	headers: Record<string, string[]>;
	/** Response body. */
	body: number[];
}

/** Public account identity information. */
export interface PublicIdentity {
	/**
	 * Address identifier for the account.
	 * 
	 * This corresponds to the address of the signing key
	 * for the account.
	 */
	address: string;
	/**
	 * Label for the account.
	 * 
	 * This is the name given to the identity vault.
	 */
	label: string;
}

/** Filter for a search query. */
export interface QueryFilter {
	/** List of tags. */
	tags: string[];
	/** List of vault identifiers. */
	folders: string[];
	/** List of type identifiers. */
	types: SecretType[];
}

/** Information about the service. */
export interface ServiceAppInfo {
	/** App name. */
	name: string;
	/** App version. */
	version: string;
	/** App build number. */
	build_number: number;
}

/** Generic command outcome. */
export enum CommandOutcome {
	/** Account not found. */
	NotFound = "notFound",
	/** Already authenticated. */
	AlreadyAuthenticated = "alreadyAuthenticated",
	/** Not authenticated. */
	NotAuthenticated = "notAuthenticated",
	/** Account was authenticated. */
	Success = "success",
	/** Authentication failed. */
	Failed = "failed",
	/** User canceled. */
	Canceled = "canceled",
	/** Timed out waiting for user input. */
	TimedOut = "timedOut",
	/** Too many attempts to authenticate. */
	Exhausted = "exhausted",
	/** Error attempting to get user input. */
	InputError = "inputError",
	/** Operation is not supported. */
	Unsupported = "unsupported",
}

/** View of documents in the search index. */
export type DocumentView = 
	/** View all documents in the search index. */
	| { kind: "all", body: {
	/** List of secret types to ignore. */
	ignoredTypes?: SecretType[];
}}
	/** View all the documents for a folder. */
	| { kind: "vault", body: string }
	/** View documents across all vaults by type identifier. */
	| { kind: "typeId", body: SecretType }
	/** View for all favorites. */
	| { kind: "favorites", body?: undefined }
	/** View documents that have one or more tags. */
	| { kind: "tags", body: string[] }
	/** Contacts of the given types. */
	| { kind: "contact", body: {
	/**
	 * Contact types to include in the results.
	 * 
	 * If no types are specified all types are included.
	 */
	include_types?: Kind[];
}}
	/** Documents with the specific identifiers. */
	| { kind: "documents", body: {
	/** Vault identifier. */
	folderId: string;
	/** Secret identifiers. */
	identifiers: string[];
}}
	/** Secrets with the associated websites. */
	| { kind: "websites", body: {
	/** Secrets that match the given target URLs. */
	matches?: string[];
	/**
	 * Exact match requires that the match targets and
	 * websites are exactly equal. Otherwise, comparison
	 * is performed using the URL origin.
	 */
	exact: boolean;
}};

/** IPC response information. */
export type IpcResponse = 
	/** Error response. */
	| { kind: "err", body: {
	/** Message identifier. */
	id: number;
	/** Message payload. */
	payload: IpcResponseError;
}}
	/** Response value. */
	| { kind: "ok", body: {
	/** Message identifier. */
	id: number;
	/** Message payload. */
	payload: IpcResponseBody;
}};

/** IPC response body. */
export type IpcResponseBody = 
	/** Response to a probe request. */
	| { kind: "probe", body?: undefined }
	/** App info. */
	| { kind: "info", body: ServiceAppInfo }
	/**
	 * App status.
	 * 
	 * Whether the app is running as determined
	 * by an active app file lock.
	 */
	| { kind: "status", body: boolean }
	/** Reply to a ping. */
	| { kind: "pong", body?: undefined }
	/** Result of opening a URL. */
	| { kind: "openUrl", body: boolean }
	/** Result invoking the local server. */
	| { kind: "http", body: LocalResponse }
	/** List of accounts. */
	| { kind: "accounts", body: AccountsList }
	/** Copy to clipboard result. */
	| { kind: "copy", body: CommandOutcome }
	/** Authenticate response. */
	| { kind: "authenticate", body: CommandOutcome }
	/** Lock response. */
	| { kind: "lock", body: CommandOutcome }
	/** Search query response. */
	| { kind: "search", body: SearchResults }
	/** Query view response. */
	| { kind: "queryView", body: SearchResults };

