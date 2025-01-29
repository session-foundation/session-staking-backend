PRAGMA journal_mode=WAL;

CREATE TABLE prices (
    token TEXT NOT NULL,
    currency TEXT NOT NULL,
    price FLOAT NOT NULL,
    market_cap FLOAT NOT NULL,
    updated_at INTEGER NOT NULL
);

CREATE INDEX prices_updated_at_idx ON prices(updated_at DESC);
CREATE INDEX prices_token_at_idx ON prices(token, updated_at DESC);
CREATE INDEX prices_token_currency_idx ON prices(token, currency, updated_at DESC);
CREATE INDEX prices_currency_idx ON prices(currency, updated_at DESC);
