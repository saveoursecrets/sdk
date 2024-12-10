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

export type ListSecret = {
  items: [name: string]: string;
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
	headers?: Headers;
	/** Request body. */
	body?: number[];
	/** Number of chunks for this message. */
	chunksLength: number;
	/** Chunk index for this message. */
	chunkIndex: number;
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
	headers?: Headers;
	/** Response body. */
	body?: number[];
	/** Number of chunks for this message. */
	chunksLength: number;
	/** Chunk index for this message. */
	chunkIndex: number;
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

/** Secret with it's associated meta data and identifier. */
export interface SecretRow {
	/** Identifier for the secret. */
	id: string;
	/** Meta data for the secret. */
	meta: SecretMeta;
	/** The data for the secret. */
	secret: Secret;
}

/** Information about the service. */
export interface ServiceAppInfo {
	/** App name. */
	name: string;
	/** App version. */
	version: string;
}

/**
 * Summary holding basic file information such as version,
 * unique identifier and name.
 */
export interface Summary {
	/** Encoding version. */
	version: number;
	/** Unique identifier for the vault. */
	id: string;
	/** Vault name. */
	name: string;
	/** Encryption cipher. */
	cipher: Cipher;
	/** Key derivation function. */
	kdf: KeyDerivation;
	/** Flags for the vault. */
	flags: VaultFlags;
}

/** Collection of custom user data. */
export interface UserData {
	/** Collection of custom user fields. */
	fields: SecretRow[];
	/** Comment for the secret. */
	comment?: string;
	/**
	 * Recovery notes.
	 * 
	 * These are notes specific for a person that might recover
	 * the vault information and is intended to provide additional
	 * information on how to use this secret in the event of an
	 * emergency.
	 */
	recoveryNote?: string;
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

/** Variants for embedded and external file secrets. */
export type FileContent = 
	/** Embedded file buffer. */
	| { kind: "embedded", body: {
	/** File name. */
	name: string;
	/**
	 * Mime type for the data.
	 * 
	 * Use application/octet-stream if no mime-type is available.
	 */
	mime: string;
	/** The binary data. */
	buffer: SecretBox<number[]>;
	/**
	 * The SHA-256 digest of the buffer.
	 * 
	 * Using the SHA-256 digest allows the checksum to be computed
	 * using the Javascript SubtleCrypto API and in Dart using the
	 * crypto package.
	 * 
	 * This is used primarily during the public migration export
	 * to identify files that have been extracted to another location
	 * in the archive rather than embedding the binary data.
	 */
	checksum: [number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number];
}}
	/** Encrypted data is stored in an external file. */
	| { kind: "external", body: {
	/** File name. */
	name: string;
	/**
	 * Mime type for the data.
	 * 
	 * Use application/octet-stream if no mime-type is available.
	 */
	mime: string;
	/**
	 * The SHA-256 digest of the buffer.
	 * 
	 * Using the SHA-256 digest allows the checksum to be computed
	 * using the Javascript SubtleCrypto API and in Dart using the
	 * crypto package.
	 * 
	 * This is used primarily during the public migration export
	 * to identify files that have been extracted to another location
	 * in the archive rather than embedding the binary data.
	 */
	checksum: [number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number, number];
}};

/** Enumeration of types of identification. */
export enum IdentityKind {
	/** Personal identification number (PIN). */
	PersonalIdNumber = "personalIdNumber",
	/** Generic id card. */
	IdCard = "idCard",
	/** Passport identification. */
	Passport = "passport",
	/** Driver license identification. */
	DriverLicense = "driverLicense",
	/** Social security identification. */
	SocialSecurity = "socialSecurity",
	/** Tax number identification. */
	TaxNumber = "taxNumber",
	/** Medical card identification. */
	MedicalCard = "medicalCard",
}

