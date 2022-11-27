use std::any::type_name;

use cosmwasm_std::{CanonicalAddr, ReadonlyStorage, StdError, StdResult, Storage};

use secret_toolkit::{
    serialization::{Bincode2, Json, Serde},
};

use serde::{de::DeserializeOwned, Deserialize, Serialize};

use crate::expiration::Expiration;

// STORAGE KEYS: used once for the contract
/// the contract
pub const CONTRACT_STORAGE_KEY: &[u8] = b"contractstorage";
/// for config
pub const CONFIG_KEY: &[u8] = b"config";
/// for the BlockInfo when the last handle was executed
pub const BLOCK_KEY: &[u8] = b"blockinfo";
/// for minters
pub const MINTERS_KEY: &[u8] = b"minters";
/// for this contract's address
pub const MY_ADDRESS_KEY: &[u8] = b"myaddr";
/// for prng seed
pub const PRNG_SEED_KEY: &[u8] = b"prngseed";
/// for the contract instantiator
pub const CREATOR_KEY: &[u8] = b"creator";
/// of public metadata
pub const PUBLIC_META_KEY: &[u8] = b"publicmeta";
/// of private metadata
pub const PRIVATE_META_KEY: &[u8] = b"privatemeta";
/// of the NFT owner list
pub const OWNERS_KEY: &[u8] = b"owners";

// PREFIXES: used for each token
/// that maps ids to indices
pub const PREFIX_MAP_TO_INDEX: &[u8] = b"map2idx";
/// that maps indices to ids
pub const PREFIX_MAP_TO_ID: &[u8] = b"idx2id";
/// of token infos
pub const PREFIX_INFOS: &[u8] = b"infos";

/// of mint run information
pub const PREFIX_MINT_RUN: &[u8] = b"mintrun";
/// of viewing keys
pub const PREFIX_VIEW_KEY: &[u8] = b"viewkeys";
/// of mint run numbers
pub const PREFIX_MINT_RUN_NUM: &[u8] = b"runnum";

/// Token contract config
#[derive(Serialize, Debug, Deserialize, Clone, PartialEq)]
pub struct Config {
    /// name of token contract
    pub name: String,
    /// token contract symbol
    pub symbol: String,
    /// admin address
    pub admin: CanonicalAddr,
    /// count of mint ops
    pub mint_cnt: u32,
    /// token count
    pub token_cnt: u32,
    /// contract status
    pub status: u8,
    /// are token IDs/count public
    pub token_supply_is_public: bool,
    /// is ownership public
    pub owners_are_public: bool,
    /// is a minter permitted to update a token's metadata
    pub minter_may_update_metadata: bool,
    pub transferable: bool,
}

/// permission to view token info/transfer tokens
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Permission {
    /// permitted address
    pub address: CanonicalAddr,
    /// list of permission expirations for this address
    pub expirations: [Option<Expiration>; 3],
}

/// permission types
#[derive(Serialize, Deserialize, Debug)]
pub enum PermissionType {
    ViewOwner,
    ViewMetadata,
    Transfer,
}

impl PermissionType {
    /// Returns usize representation of the enum variant
    pub fn to_usize(&self) -> usize {
        match self {
            PermissionType::ViewOwner => 0,
            PermissionType::ViewMetadata => 1,
            PermissionType::Transfer => 2,
        }
    }

    /// returns the number of permission types
    pub fn num_types(&self) -> usize {
        3
    }
}

/// list of one owner's tokens authorized to a single address
#[derive(Serialize, Deserialize, Debug)]
pub struct AuthList {
    /// whitelisted address
    pub address: CanonicalAddr,
    /// lists of tokens address has access to
    pub tokens: [Vec<u32>; 3],
}

/// a contract's code hash and whether they implement BatchReceiveNft
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ReceiveRegistration {
    /// code hash of the contract
    pub code_hash: String,
    /// true if the contract implements BatchReceiveNft
    pub impl_batch: bool,
}

/// Returns StdResult<()> resulting from saving an item to storage
///
/// # Arguments
///
/// * `storage` - a mutable reference to the storage this item should go to
/// * `key` - a byte slice representing the key to access the stored item
/// * `value` - a reference to the item to store
pub fn save<T: Serialize, S: Storage>(storage: &mut S, key: &[u8], value: &T) -> StdResult<()> {
    storage.set(key, &Bincode2::serialize(value)?);
    Ok(())
}

/// Removes an item from storage
///
/// # Arguments
///
/// * `storage` - a mutable reference to the storage this item is in
/// * `key` - a byte slice representing the key that accesses the stored item
pub fn remove<S: Storage>(storage: &mut S, key: &[u8]) {
    storage.remove(key);
}

/// Returns StdResult<T> from retrieving the item with the specified key.  Returns a
/// StdError::NotFound if there is no item with that key
///
/// # Arguments
///
/// * `storage` - a reference to the storage this item is in
/// * `key` - a byte slice representing the key that accesses the stored item
pub fn load<T: DeserializeOwned, S: ReadonlyStorage>(storage: &S, key: &[u8]) -> StdResult<T> {
    Bincode2::deserialize(
        &storage
            .get(key)
            .ok_or_else(|| StdError::not_found(type_name::<T>()))?,
    )
}

/// Returns StdResult<Option<T>> from retrieving the item with the specified key.
/// Returns Ok(None) if there is no item with that key
///
/// # Arguments
///
/// * `storage` - a reference to the storage this item is in
/// * `key` - a byte slice representing the key that accesses the stored item
pub fn may_load<T: DeserializeOwned, S: ReadonlyStorage>(
    storage: &S,
    key: &[u8],
) -> StdResult<Option<T>> {
    match storage.get(key) {
        Some(value) => Bincode2::deserialize(&value).map(Some),
        None => Ok(None),
    }
}

/// Returns StdResult<()> resulting from saving an item to storage using Json (de)serialization
/// because bincode2 annoyingly uses a float op when deserializing an enum
///
/// # Arguments
///
/// * `storage` - a mutable reference to the storage this item should go to
/// * `key` - a byte slice representing the key to access the stored item
/// * `value` - a reference to the item to store
pub fn json_save<T: Serialize, S: Storage>(
    storage: &mut S,
    key: &[u8],
    value: &T,
) -> StdResult<()> {
    storage.set(key, &Json::serialize(value)?);
    Ok(())
}

/// Returns StdResult<T> from retrieving the item with the specified key using Json
/// (de)serialization because bincode2 annoyingly uses a float op when deserializing an enum.  
/// Returns a StdError::NotFound if there is no item with that key
///
/// # Arguments
///
/// * `storage` - a reference to the storage this item is in
/// * `key` - a byte slice representing the key that accesses the stored item
pub fn json_load<T: DeserializeOwned, S: ReadonlyStorage>(storage: &S, key: &[u8]) -> StdResult<T> {
    Json::deserialize(
        &storage
            .get(key)
            .ok_or_else(|| StdError::not_found(type_name::<T>()))?,
    )
}

/// Returns StdResult<Option<T>> from retrieving the item with the specified key using Json
/// (de)serialization because bincode2 annoyingly uses a float op when deserializing an enum.
/// Returns Ok(None) if there is no item with that key
///
/// # Arguments
///
/// * `storage` - a reference to the storage this item is in
/// * `key` - a byte slice representing the key that accesses the stored item
pub fn json_may_load<T: DeserializeOwned, S: ReadonlyStorage>(
    storage: &S,
    key: &[u8],
) -> StdResult<Option<T>> {
    match storage.get(key) {
        Some(value) => Json::deserialize(&value).map(Some),
        None => Ok(None),
    }
}
