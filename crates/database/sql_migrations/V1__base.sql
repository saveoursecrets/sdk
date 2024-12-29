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
CREATE TRIGGER
  update_account_modified_at
AFTER UPDATE OF name ON accounts
FOR EACH ROW
BEGIN UPDATE accounts
  SET modified_at = datetime('now')
  WHERE account_id = NEW.account_id;
END;

-- Account identity login folder
CREATE TABLE IF NOT EXISTS account_logins 
(
    account_id          INTEGER             NOT NULL,
    folder_id           INTEGER             NOT NULL,

    FOREIGN KEY (account_id)
      REFERENCES accounts (account_id) ON DELETE CASCADE,
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

    -- encoding version
    version               INTEGER             NOT NULL,
    -- encryption cipher
    cipher                TEXT                NOT NULL,
    -- key derivation function
    kdf                   TEXT                NOT NULL,
    -- bit flags (little endian)
    flags                 BLOB(8)             NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS folders_identifier_idx ON folders (identifier);
CREATE INDEX IF NOT EXISTS folders_name_idx       ON folders (name);

CREATE TRIGGER
  update_folder_modified_at
AFTER UPDATE OF name, version, cipher, kdf, flags ON folders
FOR EACH ROW
BEGIN UPDATE folders
  SET modified_at = datetime('now')
  WHERE folder_id = NEW.folder_id;
END;

CREATE TABLE IF NOT EXISTS folder_secrets 
(
    secret_id             INTEGER             PRIMARY KEY NOT NULL,
    folder_id             INTEGER             NOT NULL,
    created_at            DATETIME            DEFAULT CURRENT_TIMESTAMP,
    modified_at           DATETIME            DEFAULT CURRENT_TIMESTAMP,
    -- UUID
    identifier            TEXT                NOT NULL UNIQUE,
    -- SHA256 hash of the encoded data
    commit_hash           TEXT                NOT NULL,
    -- AEAD encrypted meta data
    meta                  BLOB                NOT NULL,
    -- AEAD encrypted secret data
    secret                BLOB                NOT NULL,

    FOREIGN KEY (folder_id) REFERENCES folders (folder_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS folder_secrets_identifier_idx
  ON folder_secrets (identifier);

CREATE TRIGGER
  update_vault_modified_at
AFTER UPDATE OF meta, secret ON folder_secrets
FOR EACH ROW
BEGIN UPDATE folder_secrets
  SET modified_at = datetime('now')
  WHERE vault_id = NEW.vault_id;
END;

CREATE TABLE IF NOT EXISTS folder_events 
(
    event_id              INTEGER             PRIMARY KEY NOT NULL,
    folder_id             INTEGER             NOT NULL,
    created_at            DATETIME            DEFAULT CURRENT_TIMESTAMP,
    -- SHA256 hash of the encoded data
    commit_hash           TEXT                NOT NULL,
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
    commit_hash           TEXT                NOT NULL,
    -- Encoded event data (AccountEvent)
    event                 BLOB                NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS account_events_commit_hash_idx
  ON account_events (commit_hash);

-- Events indicating changes to encrypted files
CREATE TABLE IF NOT EXISTS file_events 
(
    event_id              INTEGER             PRIMARY KEY NOT NULL,
    account_id            INTEGER             NOT NULL,
    created_at            DATETIME            DEFAULT CURRENT_TIMESTAMP,
    -- SHA256 hash of the encoded data
    commit_hash           TEXT                NOT NULL,
    -- Encoded event data (FileEvent)
    event                 BLOB                NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
      ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS file_events_commit_hash_idx
  ON file_events (commit_hash);

