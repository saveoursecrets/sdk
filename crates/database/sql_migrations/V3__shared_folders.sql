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
CREATE TABLE IF NOT EXISTS account_shared_folder
(
    account_id          INTEGER             NOT NULL,
    folder_id           INTEGER             NOT NULL,
    
    FOREIGN KEY (account_id)
      REFERENCES accounts (account_id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id)
      REFERENCES folders (folder_id) ON DELETE CASCADE
);

-- Store folder shared access.
ALTER TABLE folders ADD COLUMN shared_access BLOB;

-- Recipients are publicly accessible user-chosen 
-- names mapped to public keys allowing discovery of 
-- people's public keys for shared folder asymmetric encryption.
CREATE TABLE IF NOT EXISTS recipients
(
    -- Account id.
    account_id                INTEGER             NOT NULL,
    -- Recipient name.
    --
    -- Should be a username or handle that would allow other 
    -- people to identify the recipient.
    recipient_name            TEXT                NOT NULL,
    -- Optional email address.
    recipient_email           TEXT,
    -- Public key for the recipient.
    recipient_public_key      TEXT                NOT NULL,
    
    FOREIGN KEY (account_id)
      REFERENCES accounts (account_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS recipients_name_idx ON recipients(recipient_name);
CREATE INDEX IF NOT EXISTS recipients_email_idx ON recipients(recipient_email);
CREATE INDEX IF NOT EXISTS recipients_public_key_idx ON recipients(recipient_public_key);
