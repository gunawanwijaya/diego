    UPDATE accounts SET
        _username       = IFNULL(CAST(@username AS TEXT),      _username),
        _key_id         = IFNULL(CAST(@key_id AS BLOB),        _key_id),
        _password       = IFNULL(CAST(@password AS BLOB),      _password),
        _passwordless   = IFNULL(CAST(@passwordless AS BLOB),  _passwordless),
        _totp_secret    = IFNULL(CAST(@totp_secret AS BLOB),   _totp_secret),
        _totp_recovery  = IFNULL(CAST(@totp_recovery AS BLOB), _totp_recovery),
        _email_address  = IFNULL(CAST(@email_address AS BLOB), _email_address),
        _phone_number   = IFNULL(CAST(@phone_number AS BLOB),  _phone_number),
        _update_key     = CAST(@update_key AS BLOB),
        _updated_at     = CAST(@updated_at AS INT)
    WHERE   CAST(@id AS BLOB) = _id
        AND CAST(@last_update_key AS BLOB) = _update_key
        AND CAST(@last_update_key AS BLOB) <> CAST(@update_key AS BLOB)
        AND CAST(@last_update_key AS BLOB) IS NOT NULL
        AND CAST(@update_key AS BLOB) IS NOT NULL
        AND CAST(@updated_at AS INT) >= _updated_at
    ;