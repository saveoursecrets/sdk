CREATE TABLE IF NOT EXISTS accounts
(
    account_id            INTEGER             PRIMARY KEY NOT NULL,
    created_at            DATETIME            DEFAULT CURRENT_TIMESTAMP,
    identifier            TEXT                NOT NULL,
    name                  TEXT                NOT NULL

);
CREATE INDEX IF NOT EXISTS accounts_name_idx ON accounts (name);

CREATE TABLE IF NOT EXISTS folders
(
    folder_id             INTEGER             PRIMARY KEY NOT NULL,
    account_id            INTEGER             NOT NULL,
    created_at            DATETIME            DEFAULT CURRENT_TIMESTAMP,
    -- UUID
    identifier            TEXT                NOT NULL,
    name                  TEXT                NOT NULL,

    FOREIGN KEY (account_id) REFERENCES accounts (account_id)
);
CREATE INDEX IF NOT EXISTS folders_name_idx ON folders (name);
