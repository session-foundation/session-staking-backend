
PRAGMA journal_mode=WAL;

CREATE TABLE service_nodes_staging (
    active BOOLEAN NOT NULL,
    contract_id INTEGER NOT NULL,
    decommission_count INTEGER NOT NULL,
    earned_downtime_blocks INTEGER NOT NULL,
    fetched_block_height INTEGER NOT NULL,
    funded BOOLEAN NOT NULL,
    is_liquidatable BOOLEAN NOT NULL,
    is_removable BOOLEAN NOT NULL,
    last_reward_block_height INTEGER NOT NULL,
--     last_reward_transaction_index INTEGER NOT NULL,
    last_uptime_proof INTEGER NOT NULL,
    lokinet_version TEXT,
    operator_address BLOB NOT NULL,
    operator_fee INTEGER NOT NULL,
    payable BOOLEAN NOT NULL,
--     portions_for_operator TEXT NOT NULL, -- too large to be an int
    pubkey_bls BLOB NOT NULL,
    pubkey_ed25519 BLOB NOT NULL,
--     pubkey_x25519 BLOB NOT NULL,
    public_ip TEXT,
    pulse_votes TEXT, -- JSON encoded dict
    quorumnet_port INTEGER,
    registration_height INTEGER NOT NULL,
    registration_hf_version INTEGER NOT NULL,
    requested_unlock_height INTEGER NOT NULL,
    service_node_pubkey BLOB NOT NULL,
    service_node_version TEXT, -- JSON encoded list of integers
    staking_requirement INTEGER NOT NULL,
    state_height INTEGER NOT NULL,
    storage_lmq_port INTEGER,
    storage_port INTEGER,
    storage_server_version TEXT, -- JSON encoded list of integers
    swarm TEXT NOT NULL,
    swarm_id TEXT NOT NULL, -- too large to be an int
    total_contributed INTEGER NOT NULL,

    PRIMARY KEY(contract_id, fetched_block_height)
);


CREATE INDEX service_nodes_staging_contract_id_idx ON service_nodes_staging(contract_id);
CREATE INDEX service_nodes_staging_fetched_block_height_desc_idx
    ON service_nodes_staging(fetched_block_height DESC);

CREATE TABLE service_nodes_contributions_staging (
    address BLOB NOT NULL,
    amount INTEGER NOT NULL,
    beneficiary BLOB,
    contract_id INTEGER NOT NULL,
    fetched_block_height INTEGER NOT NULL,

    FOREIGN KEY (contract_id, fetched_block_height) REFERENCES service_nodes_staging(contract_id, fetched_block_height),
    PRIMARY KEY (contract_id, address, fetched_block_height)
);

CREATE INDEX service_nodes_contributions_staging_contract_id_idx ON service_nodes_contributions_staging(contract_id);
CREATE INDEX service_nodes_contributions_staging_fetched_block_height_desc_idx ON service_nodes_contributions_staging(fetched_block_height DESC);
CREATE INDEX service_nodes_contributions_staging_fetched_block_height_asc_idx ON service_nodes_contributions_staging(fetched_block_height ASC);


CREATE TABLE service_nodes_main (
    active BOOLEAN NOT NULL,
    contract_id INTEGER NOT NULL,
    decommission_count INTEGER NOT NULL,
    earned_downtime_blocks INTEGER NOT NULL,
    fetched_block_height INTEGER NOT NULL,
    funded BOOLEAN NOT NULL,
    is_liquidatable BOOLEAN NOT NULL,
    is_removable BOOLEAN NOT NULL,
    last_reward_block_height INTEGER NOT NULL,
--     last_reward_transaction_index INTEGER NOT NULL,
    last_uptime_proof INTEGER NOT NULL,
    lokinet_version TEXT,
    operator_address BLOB NOT NULL,
    operator_fee INTEGER NOT NULL,
    payable BOOLEAN NOT NULL,
--     portions_for_operator TEXT NOT NULL, -- too large to be an int
    pubkey_bls BLOB NOT NULL,
    pubkey_ed25519 BLOB NOT NULL,
--     pubkey_x25519 BLOB NOT NULL,
    public_ip TEXT,
    pulse_votes TEXT, -- JSON encoded dict
    quorumnet_port INTEGER,
    registration_height INTEGER NOT NULL,
    registration_hf_version INTEGER NOT NULL,
    requested_unlock_height INTEGER NOT NULL,
    service_node_pubkey BLOB NOT NULL,
    service_node_version TEXT, -- JSON encoded list of integers
    staking_requirement INTEGER NOT NULL,
    state_height INTEGER NOT NULL,
    storage_lmq_port INTEGER,
    storage_port INTEGER,
    storage_server_version TEXT,-- JSON encoded list of integers
    swarm TEXT NOT NULL,
    swarm_id TEXT NOT NULL, -- too large to be an int
    total_contributed INTEGER NOT NULL,

    PRIMARY KEY(contract_id)
);


CREATE INDEX service_nodes_main_contract_id_idx ON service_nodes_main(contract_id);
CREATE INDEX service_nodes_main_fetched_block_height_desc_idx
    ON service_nodes_main(fetched_block_height DESC);

CREATE TABLE service_nodes_contributions_main (
    address BLOB NOT NULL,
    amount INTEGER NOT NULL,
    beneficiary BLOB,
    contract_id INTEGER NOT NULL,
    fetched_block_height INTEGER NOT NULL,

    FOREIGN KEY (contract_id) REFERENCES service_nodes_main(contract_id),
    PRIMARY KEY (contract_id, address)
);

CREATE INDEX service_nodes_contributions_main_contract_id_idx ON service_nodes_contributions_main(contract_id);
CREATE INDEX service_nodes_contributions_main_fetched_block_height_desc_idx ON service_nodes_contributions_main(fetched_block_height DESC);

CREATE TABLE network_info (
    id INTEGER PRIMARY KEY NOT NULL,
    block_hash TEXT NOT NULL,
    block_height INTEGER NOT NULL,
    block_timestamp FLOAT NOT NULL,
    hard_fork INTEGER NOT NULL,
    immutable_block_hash TEXT NOT NULL,
    immutable_block_height INTEGER NOT NULL,
    max_stakers INTEGER NOT NULL,
    min_operator_contribution INTEGER NOT NULL,
    nettype TEXT NOT NULL,
    pulse_target_timestamp INTEGER NOT NULL,
    staking_requirement INTEGER NOT NULL,
    version TEXT NOT NULL
);

CREATE INDEX network_info_block_height_idx ON network_info(block_height DESC);

CREATE TABLE arbitrum_events (
    block INTEGER NOT NULL,
    tx TEXT NOT NULL,
    name TEXT NOT NULL,
    args TEXT NOT NULL,
    PRIMARY KEY (block, tx, name)
);

CREATE INDEX arbitrum_events_block_idx ON arbitrum_events(block DESC);

CREATE TABLE contribution_contracts (
    address TEXT NOT NULL,
    fee INTEGER NOT NULL,
    operator_address TEXT NOT NULL,
    pubkey_bls BLOB NOT NULL,
    service_node_pubkey BLOB NOT NULL,
    service_node_signature BLOB NOT NULL,
    status INTEGER NOT NULL,

    PRIMARY KEY (address)
);

CREATE INDEX contribution_contracts_address_idx ON contribution_contracts(address);

CREATE TABLE contribution_contracts_contributions
(
    address             BLOB    NOT NULL,
    amount              INTEGER NOT NULL,
    beneficiary_address BLOB    NOT NULL,
    contract_address    BLOB    NOT NULL,
    reserved            INTEGER,

    FOREIGN KEY (contract_address) REFERENCES contribution_contracts (address),
    PRIMARY KEY (contract_address, address)
);

CREATE INDEX contribution_contracts_contributions_contract_address_address ON contribution_contracts_contributions(contract_address, address);
CREATE INDEX contribution_contracts_contributions_contract_address_address_amount ON contribution_contracts_contributions(contract_address, address, amount);

CREATE TABLE smart_contract_abis (
    name TEXT NOT NULL,
    abi TEXT NOT NULL,
    bytecode BLOB NOT NULL,
    deployed_bytecode BLOB NOT NULL,
    PRIMARY KEY (name)
);

CREATE TABLE smart_contracts (
    address TEXT NOT NULL,
    name TEXT NOT NULL,
    PRIMARY KEY (address),

    foreign key (name) references smart_contract_abis(name)
);

-- TODO: check if this can be better, just ported over from the old db
CREATE TABLE IF NOT EXISTS registrations (
    contract BLOB,
    operator BLOB NOT NULL,
    pubkey_bls BLOB NOT NULL,
    pubkey_ed25519 BLOB NOT NULL,
    sig_bls BLOB NOT NULL,
    sig_ed25519 BLOB NOT NULL,
    timestamp FLOAT NOT NULL DEFAULT ((julianday('now') - 2440587.5)*86400.0), /* unix epoch */

    CHECK(length(pubkey_ed25519) == 32),
    CHECK(length(pubkey_bls) == 64),
    CHECK(length(sig_ed25519) == 64),
    CHECK(length(sig_bls) == 128),
    CHECK(length(operator) == 20),
    CHECK(contract IS NULL OR length(contract) == 20)
)