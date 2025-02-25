-- Audit log
CREATE TABLE IF NOT EXISTS audit_logs
(
    log_id                INTEGER             PRIMARY KEY NOT NULL,
    created_at            DATETIME            DEFAULT CURRENT_TIMESTAMP,
    account_identifier    TEXT                NOT NULL,
    event_kind            TEXT                NOT NULL,
    event_data            TEXT
);

-- Accounts
CREATE TABLE IF NOT EXISTS accounts
(
    account_id            INTEGER             PRIMARY KEY NOT NULL,
    created_at            DATETIME            DEFAULT CURRENT_TIMESTAMP,
    modified_at           DATETIME            DEFAULT CURRENT_TIMESTAMP,

    identifier            TEXT                NOT NULL UNIQUE,
    name                  TEXT                NOT NULL
);
CREATE INDEX IF NOT EXISTS accounts_identifier_idx 
  ON accounts (identifier);
CREATE INDEX IF NOT EXISTS accounts_name_idx
  ON accounts (name);

-- Account identity login folder
CREATE TABLE IF NOT EXISTS account_login_folder
(
    account_id          INTEGER             NOT NULL,
    folder_id           INTEGER             NOT NULL,

    FOREIGN KEY (account_id)
      REFERENCES accounts (account_id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id)
      REFERENCES folders (folder_id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders (folder_id)
);

-- Account device folder
--
-- Device folders only exist on the client storage so there 
-- won't be a join on the server storage.
CREATE TABLE IF NOT EXISTS account_device_folder
(
    account_id          INTEGER             NOT NULL,
    folder_id           INTEGER             NOT NULL,

    FOREIGN KEY (account_id)
      REFERENCES accounts (account_id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id)
      REFERENCES folders (folder_id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id) REFERENCES folders (folder_id)
);

CREATE TABLE IF NOT EXISTS folders
(
    folder_id             INTEGER             PRIMARY KEY NOT NULL,
    account_id            INTEGER             NOT NULL,
    created_at            DATETIME            DEFAULT CURRENT_TIMESTAMP,
    modified_at           DATETIME            DEFAULT CURRENT_TIMESTAMP,

    -- UUID
    identifier            TEXT                NOT NULL UNIQUE,

    -- name
    name                  TEXT                NOT NULL,

    -- Salt for key derivation
    salt                  TEXT,

    -- AEAD encrypted meta data
    meta                  BLOB,

    -- encoding version
    version               INTEGER             NOT NULL,
    -- encryption cipher
    cipher                TEXT                NOT NULL,
    -- key derivation function
    kdf                   TEXT                NOT NULL,
    -- bit flags u64 (little endian)
    flags                 BLOB(8)             NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS folders_identifier_idx ON folders (identifier);
CREATE INDEX IF NOT EXISTS folders_name_idx       ON folders (name);

CREATE TABLE IF NOT EXISTS folder_secrets 
(
    secret_id             INTEGER             PRIMARY KEY NOT NULL,
    folder_id             INTEGER             NOT NULL,
    created_at            DATETIME            DEFAULT CURRENT_TIMESTAMP,
    modified_at           DATETIME            DEFAULT CURRENT_TIMESTAMP,
    -- UUID
    identifier            TEXT                NOT NULL UNIQUE,
    -- SHA256 hash of the encoded data
    commit_hash           BLOB(32)            NOT NULL,
    -- AEAD encrypted meta data
    meta                  BLOB                NOT NULL,
    -- AEAD encrypted secret data
    secret                BLOB                NOT NULL,

    FOREIGN KEY (folder_id) REFERENCES folders (folder_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS folder_secrets_identifier_idx
  ON folder_secrets (identifier);

-- Event logs for a folder
CREATE TABLE IF NOT EXISTS folder_events 
(
    event_id              INTEGER             PRIMARY KEY NOT NULL,
    folder_id             INTEGER             NOT NULL,
    created_at            DATETIME            DEFAULT CURRENT_TIMESTAMP,
    -- SHA256 hash of the encoded data
    commit_hash           BLOB(32)            NOT NULL,
    -- Encoded event data (WriteEvent)
    event                 BLOB                NOT NULL,

    FOREIGN KEY (folder_id) REFERENCES folders (folder_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS folder_events_commit_hash_idx
  ON folder_events (commit_hash);

-- Account level events
CREATE TABLE IF NOT EXISTS account_events 
(
    event_id              INTEGER             PRIMARY KEY NOT NULL,
    account_id            INTEGER             NOT NULL,
    created_at            DATETIME            DEFAULT CURRENT_TIMESTAMP,
    -- SHA256 hash of the encoded data
    commit_hash           BLOB(32)            NOT NULL,
    -- Encoded event data (AccountEvent)
    event                 BLOB                NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS account_events_commit_hash_idx
  ON account_events (commit_hash);

-- Device level events
CREATE TABLE IF NOT EXISTS device_events 
(
    event_id              INTEGER             PRIMARY KEY NOT NULL,
    account_id            INTEGER             NOT NULL,
    created_at            DATETIME            DEFAULT CURRENT_TIMESTAMP,
    -- SHA256 hash of the encoded data
    commit_hash           BLOB(32)            NOT NULL,
    -- Encoded event data (DeviceEvent)
    event                 BLOB                NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS device_events_commit_hash_idx
  ON device_events (commit_hash);

-- Events indicating changes to encrypted files
CREATE TABLE IF NOT EXISTS file_events 
(
    event_id              INTEGER             PRIMARY KEY NOT NULL,
    account_id            INTEGER             NOT NULL,
    created_at            DATETIME            DEFAULT CURRENT_TIMESTAMP,
    -- SHA256 hash of the encoded data
    commit_hash           BLOB(32)            NOT NULL,
    -- Encoded event data (FileEvent)
    event                 BLOB                NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS file_events_commit_hash_idx
  ON file_events (commit_hash);

-- Preferences, when an account_id is not set then the 
-- preferences are considered to be global (eg: language)
-- otherwise they are specific to an account.
CREATE TABLE IF NOT EXISTS preferences
(
    preference_id         INTEGER             PRIMARY KEY NOT NULL,
    account_id            INTEGER,
    created_at            DATETIME            DEFAULT CURRENT_TIMESTAMP,
    modified_at           DATETIME            DEFAULT CURRENT_TIMESTAMP,

    -- String preference key
    key                   TEXT                NOT NULL,

    -- JSON encoded data for the preference
    json_data             TEXT                NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS preferences_key_idx ON preferences (key);

-- Server remote origins for an account
CREATE TABLE IF NOT EXISTS servers
(
    server_id             INTEGER             PRIMARY KEY NOT NULL,
    account_id            INTEGER             NOT NULL,
    created_at            DATETIME            DEFAULT CURRENT_TIMESTAMP,
    modified_at           DATETIME            DEFAULT CURRENT_TIMESTAMP,

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
CREATE TABLE IF NOT EXISTS system_messages
(
    system_message_id     INTEGER             PRIMARY KEY NOT NULL,
    account_id            INTEGER             NOT NULL,
    created_at            DATETIME            DEFAULT CURRENT_TIMESTAMP,
    modified_at           DATETIME            DEFAULT CURRENT_TIMESTAMP,

    -- URN message key
    key                   TEXT                NOT NULL,

    -- JSON encoded message data
    json_data             TEXT                NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS system_messages_key_idx ON system_messages (key);
