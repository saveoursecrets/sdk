-- Folders that may be shared between accounts.
--
-- Unlike login and device folders which use a 1:1 
-- relationship via a join table this is a many to many 
-- relationship.
--
-- Each folder should be using asymmetric encryption 
-- to provide access control; the use of an asymmetric cipher 
-- should be enforced at the API level.
CREATE TABLE IF NOT EXISTS account_shared_folder
(
    account_id          INTEGER             NOT NULL,
    folder_id           INTEGER             NOT NULL,
    
    FOREIGN KEY (account_id)
      REFERENCES accounts (account_id) ON DELETE CASCADE,
    FOREIGN KEY (folder_id)
      REFERENCES folders (folder_id) ON DELETE CASCADE
);
