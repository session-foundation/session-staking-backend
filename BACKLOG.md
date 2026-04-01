# Backlog

Items sourced from unresolved review comments on [PR #4](https://github.com/session-foundation/session-staking-backend/pull/4).

## Larger Tasks

Changes that require more thought, design decisions, or have wider impact.

- **`run_fetcher.py`** — Remove the `run_fetcher.py` wrapper script; merge the app entrypoint into the app file itself using `if __name__ == "__main__":` (apply the same pattern to all other `app_<thing>.py` files); update README to reflect the change
- **`src/config_defaults.py`** — Audit all exposed config options against the principle of only exposing what genuinely needs to vary at runtime; too many options create a combinatoric explosion of possible misconfigurations and cognitive overhead — the individual items below are the specific callouts from review, but the file warrants a holistic pass
- **`src/config_defaults.py`** — Remove `rpc_shared_cache`; set `rpc_api_cache = 2` and `rpc_fetcher_cache = 1` explicitly to eliminate hidden override behaviour
- **`src/config_defaults.py`** — Merge `rpc_shared`/`rpc_api` override chain into a single `rpc_url` variable; add a comment noting it accepts either a `.sock` path or a `localhost` URL
- **`src/config_defaults.py`** — `eth_provider_urls` and `fetcher_provider_urls` — the code currently only uses the first entry; either document that multi-URL support is not yet implemented, or change both to a plain `str`
- **`src/config_defaults.py`** — Clarify and document `ws_max_run_depth` (flagged as suspicious during review)
- **`src/config_defaults.py`** — Hardcode `reconnect_delay` (2s) instead of exposing it as a config option; remove from `Backend` and inline the value at the call site
- **`src/config_defaults.py`** — Hardcode `rpc_api_usage_logging_interval` and `stale_time_seconds` instead of exposing as config; remove from `Backend` and inline at call sites
- **`src/config_defaults.py`** — Hardcode `arbitrum_rescan_safety_blocks` (60) instead of exposing as config; remove from `Backend` and inline at call sites in `fetcher.py`
- **`src/config_defaults.py`** — Hardcode `arbitrum_scan_start_chunk_size` and `refresh_rate_seconds_arbitrum` instead of exposing as config; remove from `Backend` and inline at call sites in `fetcher.py`
- **`src/config_defaults.py`** — Increase the number of DB snapshots kept from 1; a single snapshot with a ~10-minute update cycle provides too narrow a recovery window if the DB becomes corrupted
- **`src/config_defaults.py`** — Assess whether `coingecko_api_url` should be hardcoded rather than configurable
- **`src/web3client/client.py`** — Remove the `caller` parameter; for read-only contract calls no address is needed, and for write calls the address should be derived from the secret key rather than taken from config; this also removes the related config validation logic
- **`src/db/read.py` / `src/db/write.py`** — Refactor `DBReader` and `DBWriter` classes into two freestanding functions (`sql_connect_in_read_mode`, `sql_connect_in_write_mode`); reconcile feature drift between the two (e.g. logging only present in reader); align with the pattern already used in `db/util.py`
- **`src/log/perf.py`** — Replace orphan-label graceful handling with a loud assertion/crash on misuse; this removes the orphan cleanup logic from the hot path and makes the perf logger measure less of itself
