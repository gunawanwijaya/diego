    CREATE TABLE IF NOT EXISTS companies (
        _id      BLOB NOT NULL PRIMARY KEY,-- server generated ID
        _name    TEXT NOT NULL UNIQUE,     -- name
        _details TEXT NOT NULL UNIQUE)     -- details
    WITHOUT ROWID, STRICT;

    CREATE TABLE IF NOT EXISTS tags (
        _id            BLOB NOT NULL PRIMARY KEY,-- server generated ID
        _name          TEXT NOT NULL UNIQUE,     -- name
        _slug          TEXT NOT NULL UNIQUE,     -- slug using kebab-case format
        _parent_tag_id BLOB     NULL)            -- FK to `tags`._id
    WITHOUT ROWID, STRICT;

    CREATE TABLE IF NOT EXISTS products (
        _id            BLOB NOT NULL PRIMARY KEY,-- server generated ID
        _name          TEXT NOT NULL UNIQUE,     -- name
        _scanned_as    TEXT NOT NULL UNIQUE,     -- barcode/GTIN
        _printed_as    TEXT NOT NULL UNIQUE,     -- printed name
        _details       TEXT NOT NULL UNIQUE,     -- details
        _company_id    BLOB NOT NULL)            -- FK to `companies`._id
    WITHOUT ROWID, STRICT;

    CREATE TABLE IF NOT EXISTS product_tags (
        _product_id BLOB NOT NULL,-- FK to `products`._id
        _tag_id     BLOB NOT NULL,-- FK to `tags`._id
        UNIQUE (_product_id, _tag_id))
    WITHOUT ROWID, STRICT;

    CREATE TABLE IF NOT EXISTS product_prices (
        _product_id    BLOB NOT NULL,-- FK to `products`._id
        _buying_price  BLOB NOT NULL,-- decimal support
        _selling_price BLOB NOT NULL,-- decimal support
        _started_at    BLOB NOT NULL,-- datetime
        UNIQUE (_product_id, _started_at))
    WITHOUT ROWID, STRICT;

    CREATE TABLE IF NOT EXISTS product_stocks (
        _product_id    BLOB NOT NULL,       -- FK to `products`._id
        _sku           TEXT NOT NULL UNIQUE,-- server generated text
        _qty           BLOB NOT NULL,       -- decimal support of smallest unit possible
        _received_at   BLOB NOT NULL,       -- datetime
        _expired_at    BLOB NOT NULL,       -- datetime
        UNIQUE (_product_id, _received_at))
    WITHOUT ROWID, STRICT;

    CREATE TABLE IF NOT EXISTS cart_items (
        _sort_key   INTEGER NOT NULL,-- FK to `products`._id
        _buyer_id   BLOB    NOT NULL,-- FK to `buyers`._id
        _product_id BLOB    NOT NULL,-- FK to `products`._id
        _qty        BLOB    NOT NULL,-- decimal support
        UNIQUE (_buyer_id, _product_id),
        UNIQUE (_buyer_id, _sort_key))
    WITHOUT ROWID, STRICT;

    CREATE TABLE IF NOT EXISTS cart_items (
        _sort_key   INTEGER NOT NULL,-- FK to `products`._id
        _buyer_id   BLOB    NOT NULL,-- FK to `buyers`._id
        _product_id BLOB    NOT NULL,-- FK to `products`._id
        _qty        BLOB    NOT NULL,-- decimal support
        UNIQUE (_buyer_id, _product_id),
        UNIQUE (_buyer_id, _sort_key))
    WITHOUT ROWID, STRICT;
