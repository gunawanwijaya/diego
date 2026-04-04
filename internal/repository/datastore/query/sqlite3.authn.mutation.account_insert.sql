    INSERT INTO accounts (
        _id, _username, _key_id, _password, _passwordless, _totp_secret, _totp_recovery, _email_address, _phone_number, _update_key, _updated_at
    ) SELECT
        CAST(@id AS BLOB),
        CAST(@username AS TEXT),
        CAST(@key_id AS BLOB),
        CAST(@password AS BLOB),
        CAST(@passwordless AS BLOB),
        CAST(@totp_secret AS BLOB),
        CAST(@totp_recovery AS BLOB),
        CAST(@email_address AS BLOB),
        CAST(@phone_number AS BLOB),
        CAST(@update_key AS BLOB),
        CAST(@updated_at AS INT)
    WHERE @id       NOT IN (SELECT _id FROM accounts)
    AND   @username NOT IN (SELECT _username FROM accounts)
    ;