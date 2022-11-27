#![allow(clippy::large_enum_variant)]
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

use cosmwasm_std::{Binary, Coin, HumanAddr};

// use crate::mint_run::{MintRunInfo, SerialNumber};
use crate::token::{Metadata};

/// Instantiation message
#[derive(Serialize, Deserialize, JsonSchema)]
pub struct InitMsg {
    /// name of token contract
    pub name: String,
    /// token contract symbol
    pub symbol: String,
    /// optional admin address, env.message.sender if missing
    pub admin: Option<HumanAddr>,
    /// entropy used for prng seed
    pub entropy: String,
    /// optional privacy configuration for the contract
    pub config: Option<InitConfig>,
    /// optional callback message to execute after instantiation.  This will
    /// most often be used to have the token contract provide its address to a
    /// contract that instantiated it, but it could be used to execute any
    /// contract
    pub post_init_callback: Option<PostInitCallback>,
}

/// This type represents optional configuration values.
/// All values are optional and have defaults which are more private by default,
/// but can be overridden if necessary
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct InitConfig {
    /// indicates whether the token IDs and the number of tokens controlled by the contract are
    /// public.  If the token supply is private, only minters can view the token IDs and
    /// number of tokens controlled by the contract
    /// default: False
    pub public_token_supply: Option<bool>,
    /// indicates whether token ownership is public or private.  A user can still change whether the
    /// ownership of their tokens is public or private
    /// default: False
    pub public_owners: Option<bool>,
    /// indicates whether a minter is permitted to update a token's metadata
    /// default: True
    pub minter_may_update_metadata: Option<bool>,
    pub transferable: Option<bool>,
}

impl Default for InitConfig {
    fn default() -> Self {
        InitConfig {
            public_token_supply: Some(false),
            public_owners: Some(false),
            minter_may_update_metadata: Some(true),
            transferable: Some(true),
        }
    }
}

/// info needed to perform a callback message after instantiation
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct PostInitCallback {
    /// the callback message to execute
    pub msg: Binary,
    /// address of the contract to execute
    pub contract_address: HumanAddr,
    /// code hash of the contract to execute
    pub code_hash: String,
    /// list of native Coin to send with the callback message
    pub send: Vec<Coin>,
}

#[derive(Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum HandleMsg {
    /// mint new token
    MintNft {
        /// optional token id. if omitted, use current token index
        // token_id: Option<String>,
        /// optional owner address. if omitted, owned by the message sender
        owner: Option<HumanAddr>,
        /// optional serial number for this token
        // serial_number: Option<SerialNumber>,
        /// optionally true if the token is transferable.  Defaults to true if omitted
        // transferable: Option<bool>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// Mint multiple tokens
    BatchMintNft {
        /// list of mint operations to perform
        mints: Vec<Mint>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// create a mint run of clones that will have MintRunInfos showing they are serialized
    /// copies in the same mint run with the specified quantity.  Mint_run_id can be used to
    /// track mint run numbers in subsequent MintNftClones calls.  So, if provided, the first
    /// MintNftClones call will have mint run number 1, the next time MintNftClones is called
    /// with the same mint_run_id, those clones will have mint run number 2, etc...  If no
    /// mint_run_id is specified, the clones will not have any mint run number assigned to their
    /// MintRunInfos.  Because this mints to a single address, there is no option to specify
    /// that the clones are non-transferable as there is no foreseen reason for someone to have
    /// multiple copies of an nft that they can never send to others
    MintNftClones {
        /// optional mint run ID
        // mint_run_id: Option<String>,
        /// number of clones to mint
        quantity: u32,
        /// optional owner address. if omitted, owned by the message sender
        owner: Option<HumanAddr>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// set the public and/or private metadata.  This can be called by either the token owner or
    /// a valid minter if they have been given this power by the appropriate config values
    SetMetadata {
        /// the optional new public metadata
        public_metadata: Option<Metadata>,
        /// the optional new private metadata
        private_metadata: Option<Metadata>,
        /// optional message length padding
        padding: Option<String>,
    },
    /// transfer a token if it is transferable
    TransferNft {
        /// recipient of the transfer
        recipient: HumanAddr,
        /// optional message length padding
        padding: Option<String>,
    },
    /// transfer many tokens and fails if any are non-transferable
    BatchTransferNft {
        /// list of transfers to perform
        transfers: Vec<Transfer>,
        /// optional message length padding
        padding: Option<String>,
    },
    RetrieveMetadata {
        padding: Option<String>,
    },
    RetrieveOwners {
        padding: Option<String>,
    },
    /// create a viewing key
    CreateViewingKey {
        /// entropy String used in random key generation
        entropy: String,
        /// optional message length padding
        padding: Option<String>,
    },
    /// change address with administrative power
    ChangeAdmin {
        /// address with admin authority
        address: HumanAddr,
        /// optional message length padding
        padding: Option<String>,
    },
    /// set contract status level to determine which functions are allowed.  StopTransactions
    /// status prevent mints, burns, sends, and transfers, but allows all other functions
    SetContractStatus {
        /// status level
        level: ContractStatus,
        /// optional message length padding
        padding: Option<String>,
    },
}

/// token mint info used when doing a BatchMint
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct Mint {
    /// optional owner address, owned by the minter otherwise
    pub owner: Option<HumanAddr>,
}

/// token transfer info used when doing a BatchTransferNft
#[derive(Serialize, Deserialize, JsonSchema, Clone, Debug)]
pub struct Transfer {
    /// recipient of the transferred tokens
    pub recipient: HumanAddr,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum HandleAnswer {
    /// MintNft will also display the minted token's ID in the log attributes under the
    /// key `minted` in case minting was done as a callback message
    MintNft {
        // token_id: String,
    },
    /// BatchMintNft will also display the minted tokens' IDs in the log attributes under the
    /// key `minted` in case minting was done as a callback message
    BatchMintNft {
        // token_ids: Vec<String>,
    },
    /// Displays the token ids of the first minted NFT and the last minted NFT.  Because these
    /// are serialized clones, the ids of all the tokens minted in between should be easily
    /// inferred.  MintNftClones will also display the minted tokens' IDs in the log attributes
    /// under the keys `first_minted` and `last_minted` in case minting was done as a callback message
    MintNftClones {
        /// token id of the first minted clone
        first_minted: String,
        /// token id of the last minted clone
        last_minted: String,
    },
    SetMetadata {
        status: ResponseStatus,
    },
    TransferNft {
        status: ResponseStatus,
    },
    BatchTransferNft {
        status: ResponseStatus,
    },
    RetrieveMetadata {
        public_metadata: Option<Metadata>,
        private_metadata: Option<Metadata>,
        display_private_metadata_error: Option<String>,
    },
    RetrieveOwners {
        owners: Vec<HumanAddr>,
    },
    /// response from both setting and creating a viewing key
    ViewingKey {
        key: String,
    },
    ChangeAdmin {
        status: ResponseStatus,
    },
    SetContractStatus {
        status: ResponseStatus,
    },
}

/// the address and viewing key making an authenticated query request
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct ViewerInfo {
    /// querying address
    pub address: HumanAddr,
    /// authentication key string
    pub viewing_key: String,
}


#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum QueryMsg {
    /// display the contract's configuration
    ContractConfig {},
    /// display the number of tokens controlled by the contract.  The token supply must
    /// either be public, or the querier must be an authenticated minter
    NumTokens {
        /// optional address and key requesting to view the number of tokens
        viewer: Option<ViewerInfo>,
    },
    /// displays all the information about a token that the viewer has permission to
    /// see.  This may include the owner, the public metadata, the private metadata, royalty
    /// information, mint run information, whether the token is unwrapped, whether the token is
    /// transferable, and the token and inventory approvals
    NftDossier {
        // token_id: String,
        /// optional address and key requesting to view the token information
        viewer: Option<ViewerInfo>,
    },
}

/// the token id and nft dossier info of a single token response in a batch query
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
pub struct BatchNftDossierElement {
    // pub token_id: String,
    pub contract_admin: Option<HumanAddr>,
    pub public_metadata: Option<Metadata>,
    pub private_metadata: Option<Metadata>,
    pub display_private_metadata_error: Option<String>,
    // pub mint_run_info: Option<MintRunInfo>,
    /// true if tokens are transferable
    pub transferable: bool,
    pub owners_are_public: bool,
}

#[derive(Serialize, Deserialize, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum QueryAnswer {
    ContractInfo {
        name: String,
        symbol: String,
    },
    ContractConfig {
        token_supply_is_public: bool,
        owners_are_public: bool,
        minter_may_update_metadata: bool,
        tokens_are_transferable: bool,
    },

    NumTokens {
        count: u32,
    },
    NftDossier {
        owner: Option<HumanAddr>,
        public_metadata: Option<Metadata>,
        private_metadata: Option<Metadata>,
        display_private_metadata_error: Option<String>,
        // mint_run_info: Option<MintRunInfo>,
        transferable: bool,
        owners_are_public: bool,
    },
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ResponseStatus {
    Success,
    Failure,
}

#[derive(Serialize, Deserialize, Clone, PartialEq, JsonSchema, Debug)]
#[serde(rename_all = "snake_case")]
pub enum ContractStatus {
    Normal,
    StopTransactions,
    StopAll,
}

impl ContractStatus {
    /// Returns u8 representation of the ContractStatus
    pub fn to_u8(&self) -> u8 {
        match self {
            ContractStatus::Normal => 0,
            ContractStatus::StopTransactions => 1,
            ContractStatus::StopAll => 2,
        }
    }
}