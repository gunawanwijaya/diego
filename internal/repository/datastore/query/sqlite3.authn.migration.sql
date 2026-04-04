    CREATE TABLE IF NOT EXISTS accounts (
        _id            BLOB NOT NULL PRIMARY KEY,-- server generated ID
        _username      TEXT NOT NULL UNIQUE,     -- username
        _key_id        BLOB NOT NULL,            -- server owned key ID to operate with encrypted value
        _password      BLOB NOT NULL,            -- hashed + encrypted
        _passwordless  BLOB     NULL,            -- encrypted token contains
        _totp_secret   BLOB     NULL,            -- encrypted
        _totp_recovery BLOB     NULL,            -- hashed + encrypted
        _email_address BLOB     NULL,            -- hashed
        _phone_number  BLOB     NULL,            -- hashed
        _update_key    BLOB NOT NULL,            -- needed in update query
        _updated_at    INT  NOT NULL)            -- last update (unix time in seconds)
    WITHOUT ROWID, STRICT;

    CREATE TABLE IF NOT EXISTS account_attributes (
        _id         BLOB NOT NULL PRIMARY KEY,-- server generated ID
        _account_id BLOB NOT NULL,            -- FK to `accounts`._id
        _type       INT  NOT NULL,            -- reflected as enum on server side
        _key_id     BLOB     NULL,            -- server owned key ID to operate with encrypted value
        _ciphertext BLOB     NULL,            -- encrypted value
        _plaintext  BLOB     NULL,            -- unencrypted value
        _started_at INT  NOT NULL,            -- recorded time of attribute to start
        _expired_at INT  NOT NULL,            -- recorded time of attribute to end - there would be daemon to delete all expired records
        _updated_at INT  NOT NULL)            -- recorded time of last update (unix time in seconds)
    WITHOUT ROWID, STRICT;
