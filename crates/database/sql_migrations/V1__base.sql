-- We use 'NOT NULL' instead of 'DEFAULT CURRENT_TIMESTAMP' for 'DATETIME'
-- columns as the default SQLite datetime string format is non-standard
-- and we use RFC3339 datetime every where else in the code so 
-- 'NOT NULL' defers the datetime format to the client code which 
-- should always be RFC3339.

-- Audit log
CREATE TABLE IF NOT EXISTS audit_logs
(
    log_id                INTEGER             PRIMARY KEY NOT NULL,
    created_at            DATETIME            NOT NULL,
    account_identifier    TEXT                NOT NULL,
    event_kind            TEXT                NOT NULL,
    -- Optional associated data encoded as JSON.
    event_data            TEXT
);

-- User accounts.
CREATE TABLE IF NOT EXISTS accounts
(
    account_id            INTEGER             PRIMARY KEY NOT NULL,
    created_at            DATETIME            NOT NULL,
    modified_at           DATETIME            NOT NULL,
    
    -- Hex-encoded string representation of an account ID.
    -- Starts with `0x` followed by 20 hex-encoded bytes.
    identifier            TEXT                NOT NULL UNIQUE,
    name                  TEXT                NOT NULL
);
CREATE INDEX IF NOT EXISTS accounts_identifier_idx 
  ON accounts (identifier);
CREATE INDEX IF NOT EXISTS accounts_name_idx
  ON accounts (name);

-- Account identity login folder.
CREATE TABLE IF NOT EXISTS account_login_folder
(
    account_id          INTEGER             NOT NULL,
    folder_id           INTEGER             NOT NULL,
    
    FOREIGN KEY (account_id)
      REFERENCES accounts (account_id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id)
      REFERENCES folders (folder_id) ON DELETE CASCADE
);

-- Account device folder
--
-- Device folders only exist on the client storage so there 
-- won't be a join on the server storage.
--
-- But servers do contain the device event logs in `device_events` 
-- to determine which device public keys are authorized.
CREATE TABLE IF NOT EXISTS account_device_folder
(
    account_id          INTEGER             NOT NULL,
    folder_id           INTEGER             NOT NULL,

    FOREIGN KEY (account_id)
      REFERENCES accounts (account_id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id)
      REFERENCES folders (folder_id) ON DELETE CASCADE
);

-- Folders.
--
-- All folders are stored here whether they are system folders 
-- (such as the login and device folders) or user-defined folders.
--
-- Queries check the relevant join tables to filter the system folders 
-- from user-defined folders.
CREATE TABLE IF NOT EXISTS folders
(
    folder_id             INTEGER             PRIMARY KEY NOT NULL,
    account_id            INTEGER             NOT NULL,
    created_at            DATETIME            NOT NULL,
    modified_at           DATETIME            NOT NULL,

    -- UUID
    identifier            TEXT                NOT NULL UNIQUE,

    -- Name
    name                  TEXT                NOT NULL,

    -- Salt for key derivation
    salt                  TEXT,

    -- Encoded AEAD encrypted folder meta data
    meta                  BLOB,

    -- Encoding version
    version               INTEGER             NOT NULL,

    -- Encryption cipher
    cipher                TEXT                NOT NULL,

    -- Key derivation function
    kdf                   TEXT                NOT NULL,

    -- Bit flags u64 (little endian)
    flags                 BLOB(8)             NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS folders_identifier_idx ON folders (identifier);
CREATE INDEX IF NOT EXISTS folders_name_idx       ON folders (name);

-- Secrets for a folder.
--
-- Server-side storage won't create any rows here as vault data 
-- is stored head-only; syncing is performed using the folder event logs.
CREATE TABLE IF NOT EXISTS folder_secrets 
(
    secret_id             INTEGER             PRIMARY KEY NOT NULL,
    folder_id             INTEGER             NOT NULL,
    created_at            DATETIME            NOT NULL,
    modified_at           DATETIME            NOT NULL,

    -- UUID
    identifier            TEXT                NOT NULL UNIQUE,

    -- SHA256 hash of the encoded data
    commit_hash           BLOB(32)            NOT NULL,

    -- Encoded AEAD encrypted secret meta data
    meta                  BLOB                NOT NULL,

    -- Encoded AEAD encrypted secret data
    secret                BLOB                NOT NULL,

    FOREIGN KEY (folder_id) REFERENCES folders (folder_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS folder_secrets_identifier_idx
  ON folder_secrets (identifier);

-- Event logs for a folder.
CREATE TABLE IF NOT EXISTS folder_events 
(
    event_id              INTEGER             PRIMARY KEY NOT NULL,
    folder_id             INTEGER             NOT NULL,
    created_at            DATETIME            NOT NULL,

    -- SHA256 hash of the encoded data
    commit_hash           BLOB(32)            NOT NULL,

    -- Encoded event data (WriteEvent)
    event                 BLOB                NOT NULL,

    FOREIGN KEY (folder_id) REFERENCES folders (folder_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS folder_events_commit_hash_idx
  ON folder_events (commit_hash);

-- Account level events.
CREATE TABLE IF NOT EXISTS account_events 
(
    event_id              INTEGER             PRIMARY KEY NOT NULL,
    account_id            INTEGER             NOT NULL,
    created_at            DATETIME            NOT NULL,

    -- SHA256 hash of the encoded data
    commit_hash           BLOB(32)            NOT NULL,

    -- Encoded event data (AccountEvent)
    event                 BLOB                NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS account_events_commit_hash_idx
  ON account_events (commit_hash);

-- Device level events.
CREATE TABLE IF NOT EXISTS device_events 
(
    event_id              INTEGER             PRIMARY KEY NOT NULL,
    account_id            INTEGER             NOT NULL,
    created_at            DATETIME            NOT NULL,

    -- SHA256 hash of the encoded data
    commit_hash           BLOB(32)            NOT NULL,

    -- Encoded event data (DeviceEvent)
    event                 BLOB                NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS device_events_commit_hash_idx
  ON device_events (commit_hash);

-- Events indicating changes to encrypted files.
CREATE TABLE IF NOT EXISTS file_events 
(
    event_id              INTEGER             PRIMARY KEY NOT NULL,
    account_id            INTEGER             NOT NULL,
    created_at            DATETIME            NOT NULL,

    -- SHA256 hash of the encoded data
    commit_hash           BLOB(32)            NOT NULL,

    -- Encoded event data (FileEvent)
    event                 BLOB                NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS file_events_commit_hash_idx
  ON file_events (commit_hash);

-- Global and account preferences.
--
-- When an account_id is not set then the preferences are 
-- considered to be global (eg: language).
-- Otherwise the preferences are specific to an account.
CREATE TABLE IF NOT EXISTS preferences
(
    preference_id         INTEGER             PRIMARY KEY NOT NULL,
    account_id            INTEGER,
    created_at            DATETIME            NOT NULL,
    modified_at           DATETIME            NOT NULL,

    -- String preference key
    key                   TEXT                NOT NULL,

    -- JSON encoded data for the preference
    json_data             TEXT                NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS preferences_key_idx ON preferences (key);

-- Server remote origins for an account.
CREATE TABLE IF NOT EXISTS servers
(
    server_id             INTEGER             PRIMARY KEY NOT NULL,
    account_id            INTEGER             NOT NULL,
    created_at            DATETIME            NOT NULL,
    modified_at           DATETIME            NOT NULL,

    -- Server name
    name                  TEXT                NOT NULL,

    -- Server URL
    url                   TEXT                NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS servers_name_idx ON servers (name);
CREATE INDEX IF NOT EXISTS servers_url_idx ON servers (url);

-- System messages
--
-- System messages are notifications displayed to the user in the 
-- context of the app to notify of possible issues such as a sync 
-- failure or other information like a due date for a backup or 
-- new software release.
CREATE TABLE IF NOT EXISTS system_messages
(
    system_message_id     INTEGER             PRIMARY KEY NOT NULL,
    account_id            INTEGER             NOT NULL,
    created_at            DATETIME            NOT NULL,
    modified_at           DATETIME            NOT NULL,

    -- URN message key
    key                   TEXT                NOT NULL,

    -- JSON encoded message data
    json_data             TEXT                NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS system_messages_key_idx ON system_messages (key);
