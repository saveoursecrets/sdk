-- Global config.
--
-- Application wide configuration settings such as the binary encoding
-- version. We also include an encoding version for vaults but we should 
-- always be using the same encoding across the app so it's better to 
-- store it here.
CREATE TABLE IF NOT EXISTS global_config
(
    config_id             INTEGER             PRIMARY KEY NOT NULL,
    created_at            DATETIME            NOT NULL,
    modified_at           DATETIME            NOT NULL,
    -- Binary encoding version
    -- Version 1 is the binary stream implementation
    -- Version 2 is protobuf encoding
    binary_encoding       INTEGER             DEFAULT 1
);
