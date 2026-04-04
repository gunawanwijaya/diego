    SELECT
        _id,
        _username,
        _key_id,
        _password,
        _passwordless,
        _totp_secret,
        _totp_recovery,
        _email_address,
        _phone_number,
        _update_key,
        _updated_at
    FROM accounts
    WHERE  _id = @id
        OR _username = @username OR _username = @lookup
        OR _email_address = @email_address OR _email_address = @lookup
        OR _phone_number = @phone_number OR _phone_number = @lookup
        OR _key_id = @key_id