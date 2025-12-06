-- Folders that may be shared between accounts.
--
-- Unlike login and device folders which use a 1:1 
-- relationship via a join table this is a many to many 
-- relationship.
--
-- Each folder should be using asymmetric encryption 
-- to provide access control; the use of an asymmetric cipher 
-- should be enforced at the API level.
--
-- The owner account_id can be determined by looking at the 
-- account_id in the folders table.
CREATE TABLE IF NOT EXISTS shared_folders
(
    -- Shared folder id.
    shared_folder_id    INTEGER             PRIMARY KEY NOT NULL,
    -- Account id.
    account_id          INTEGER             NOT NULL,
    -- Folder id.
    folder_id           INTEGER             NOT NULL,
    
    FOREIGN KEY (account_id)
      REFERENCES accounts (account_id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id)
      REFERENCES folders (folder_id) ON DELETE CASCADE,

    UNIQUE (account_id, folder_id)
);

-- Recipients with access to a shared folder.
CREATE TABLE IF NOT EXISTS shared_folder_recipients
(
    -- Shared folder id.
    shared_folder_id    INTEGER             NOT NULL,
    -- Recipient id.
    recipient_id        INTEGER             NOT NULL,
    -- Whether this recipient created the shared folder.
    is_creator          INTEGER             NOT NULL DEFAULT 0,
    
    FOREIGN KEY (shared_folder_id)
      REFERENCES shared_folders (shared_folder_id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id)
      REFERENCES recipients (recipient_id) ON DELETE CASCADE,

    UNIQUE (shared_folder_id, recipient_id)
);

-- Store folder shared access.
ALTER TABLE folders ADD COLUMN shared_access BLOB;

-- Recipients are publicly accessible user-chosen 
-- names mapped to public keys allowing discovery of 
-- people's public keys for shared folder asymmetric encryption.
CREATE TABLE IF NOT EXISTS recipients
(
    -- Recipient id.
    recipient_id              INTEGER             PRIMARY KEY NOT NULL,
    -- Account id.
    account_id                INTEGER             NOT NULL,
    -- Created date and time.
    created_at                DATETIME            NOT NULL,
    -- Last modiifed date and time.
    modified_at               DATETIME            NOT NULL,
    -- Recipient name.
    --
    -- Should be a username or handle that would allow other 
    -- people to identify the recipient.
    recipient_name            TEXT                NOT NULL,
    -- Optional email address.
    recipient_email           TEXT,
    -- Public key for the recipient.
    recipient_public_key      TEXT                NOT NULL,
    -- Indicate the key has been revoked.
    revoked                   INTEGER             NOT NULL DEFAULT 0,
    
    FOREIGN KEY (account_id)
      REFERENCES accounts (account_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS recipients_public_key_idx ON recipients(recipient_public_key);

CREATE VIRTUAL TABLE recipients_fts USING fts5(
  recipient_name, 
  recipient_email, 
  content='recipients', 
  content_rowid='recipient_id',
  tokenize='trigram'
);

CREATE TRIGGER recipients_ai AFTER INSERT ON recipients BEGIN
  INSERT INTO recipients_fts(rowid, recipient_name, recipient_email)
  VALUES (new.recipient_id, new.recipient_name, new.recipient_email);
END;

CREATE TRIGGER recipients_ad AFTER DELETE ON recipients BEGIN
  INSERT INTO recipients_fts(recipients_fts, rowid, recipient_name, recipient_email)
  VALUES('delete', old.recipient_id, old.recipient_name, old.recipient_email);
END;

CREATE TRIGGER recipients_au AFTER UPDATE ON recipients BEGIN
  INSERT INTO recipients_fts(recipients_fts, rowid, recipient_name, recipient_email)
  VALUES('delete', old.recipient_id, old.recipient_name, old.recipient_email);

  INSERT INTO recipients_fts(rowid, recipient_name, recipient_email)
  VALUES (new.recipient_id, new.recipient_name, new.recipient_email);
END;

-- Invite a recipient to join a shared folder.
CREATE TABLE IF NOT EXISTS folder_invites
(
    -- Folder invite id.
    folder_invite_id            INTEGER             PRIMARY KEY NOT NULL,
    -- Created date and time.
    created_at                  DATETIME            NOT NULL,
    -- Modified date and time.
    modified_at                 DATETIME            NOT NULL,
    -- Recipient sending the invite.
    from_recipient_id           INTEGER             NOT NULL,
    -- Recipient receiving the invite.
    to_recipient_id             INTEGER             NOT NULL,
    -- Folder being shared.
    folder_id                   INTEGER             NOT NULL,
    -- Status of the invite.
    invite_status               INTEGER             NOT NULL DEFAULT 0,
    
    FOREIGN KEY (from_recipient_id)
      REFERENCES recipients (recipient_id) ON DELETE CASCADE,
    FOREIGN KEY (to_recipient_id)
      REFERENCES recipients (recipient_id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id)
      REFERENCES folders (folder_id) ON DELETE CASCADE,

    UNIQUE (from_recipient_id, to_recipient_id, folder_id)
);
