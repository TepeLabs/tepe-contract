use cosmwasm_std::{
    log, to_binary, Api, Binary, CanonicalAddr, CosmosMsg, Env, Extern, HandleResponse,
    HandleResult, HumanAddr, InitResponse, InitResult, Querier, QueryResult, ReadonlyStorage,
    StdError, StdResult, Storage, WasmMsg,
};
use cosmwasm_storage::{PrefixedStorage, ReadonlyPrefixedStorage};
/// This contract implements SNIP-721 standard:
/// https://github.com/SecretFoundation/SNIPs/blob/master/SNIP-721.md
// use std::collections::HashSet;

use secret_toolkit::{
    utils::{pad_handle_result, pad_query_result},
};

// use crate::inventory::{Inventory};
// use crate::mint_run::{SerialNumber, StoredMintRunInfo};
use crate::msg::{
    BatchNftDossierElement, ContractStatus,
    HandleAnswer, HandleMsg, InitMsg, Mint, QueryAnswer, QueryMsg,
    ResponseStatus::Success, Transfer, ViewerInfo,
};
use crate::rand::sha_256;
use crate::state::{
    load, may_load, save,
    Config, BLOCK_KEY, MY_ADDRESS_KEY,
    CONFIG_KEY, CREATOR_KEY, MINTERS_KEY,
    PRIVATE_META_KEY, PUBLIC_META_KEY, OWNERS_KEY,
    PREFIX_VIEW_KEY, PRNG_SEED_KEY,
};
use crate::token::{Metadata};
use crate::viewing_key::{ViewingKey, VIEWING_KEY_SIZE};

/// pad handle responses and log attributes to blocks of 256 bytes to prevent leaking info based on
/// response size
pub const BLOCK_SIZE: usize = 256;
/// max number of token ids to keep in id list block
pub const ID_BLOCK_SIZE: u32 = 64;

////////////////////////////////////// Init ///////////////////////////////////////
/// Returns InitResult
///
/// Initializes the contract
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - InitMsg passed in with the instantiation message
pub fn init<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: InitMsg,
) -> InitResult {
    let creator_raw = deps.api.canonical_address(&env.message.sender)?;
    save(&mut deps.storage, CREATOR_KEY, &creator_raw)?;
    let owners_vec_init: Vec<CanonicalAddr> = Vec::new();
    save(&mut deps.storage, OWNERS_KEY, &owners_vec_init)?;
    save(
        &mut deps.storage,
        MY_ADDRESS_KEY,
        &deps.api.canonical_address(&env.contract.address)?,
    )?;
    let admin_raw = msg
        .admin
        .map(|a| deps.api.canonical_address(&a))
        .transpose()?
        .unwrap_or(creator_raw);
    let prng_seed: Vec<u8> = sha_256(base64::encode(msg.entropy).as_bytes()).to_vec();
    let init_config = msg.config.unwrap_or_default();

    let config = Config {
        name: msg.name,
        symbol: msg.symbol,
        admin: admin_raw.clone(),
        mint_cnt: 0,
        token_cnt: 0,
        status: ContractStatus::Normal.to_u8(),
        token_supply_is_public: init_config.public_token_supply.unwrap_or(false),
        owners_are_public: init_config.public_owners.unwrap_or(false),
        minter_may_update_metadata: init_config.minter_may_update_metadata.unwrap_or(true),
        transferable: init_config.transferable.unwrap_or(true),
    };

    let minters = vec![admin_raw];
    save(&mut deps.storage, CONFIG_KEY, &config)?;
    save(&mut deps.storage, MINTERS_KEY, &minters)?;
    save(&mut deps.storage, PRNG_SEED_KEY, &prng_seed)?;
    // TODO remove this after BlockInfo becomes available to queries
    save(&mut deps.storage, BLOCK_KEY, &env.block)?;

    // perform the post init callback if needed
    let messages: Vec<CosmosMsg> = if let Some(callback) = msg.post_init_callback {
        let execute = WasmMsg::Execute {
            msg: callback.msg,
            contract_addr: callback.contract_address,
            callback_code_hash: callback.code_hash,
            send: callback.send,
        };
        vec![execute.into()]
    } else {
        Vec::new()
    };
    Ok(InitResponse {
        messages,
        log: vec![],
    })
}

///////////////////////////////////// Handle //////////////////////////////////////
/// Returns HandleResult
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `msg` - HandleMsg passed in with the execute message
pub fn handle<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    msg: HandleMsg,
) -> HandleResult {
    save(&mut deps.storage, BLOCK_KEY, &env.block)?;
    let mut config: Config = load(&deps.storage, CONFIG_KEY)?;  // so this loads the config part of the contract for every handle message

    let response = match msg {
        HandleMsg::MintNft {
            owner,
            ..
        } => mint(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            owner,
        ),
        HandleMsg::BatchMintNft { mints, .. } => batch_mint(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            mints,
        ),
        HandleMsg::MintNftClones {
            quantity,
            owner,
            ..
        } => mint_clones(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            quantity,
            owner,
        ),
        HandleMsg::SetMetadata {
            public_metadata,
            private_metadata,
            ..
        } => set_metadata(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            public_metadata,
            private_metadata,
        ),
        HandleMsg::TransferNft {
            recipient,
            // token_id,
            ..
        } => transfer_nft(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            recipient,
            // token_id,
        ),
        HandleMsg::BatchTransferNft { transfers, .. } => batch_transfer_nft(
            deps,
            env,
            &mut config,
            ContractStatus::Normal.to_u8(),
            transfers,
        ),
        HandleMsg::RetrieveMetadata { .. } => retrieve_metadata(
            deps,
            env,
            &config,
            ContractStatus::Normal.to_u8(),
        ),
        HandleMsg::RetrieveOwners { .. } => retrieve_owners(
            deps,
            env,
            &config,
            ContractStatus::Normal.to_u8(),
        ),
        HandleMsg::CreateViewingKey { entropy, .. } => create_key(
            deps,
            env,
            &config,
            ContractStatus::StopTransactions.to_u8(),
            &entropy,
        ),
        HandleMsg::ChangeAdmin { address, .. } => change_admin(
            deps,
            env,
            &mut config,
            ContractStatus::StopTransactions.to_u8(),
            &address,
        ),
        HandleMsg::SetContractStatus { level, .. } => {
            set_contract_status(deps, env, &mut config, level)
        }
    };
    pad_handle_result(response, BLOCK_SIZE)
}

/// Returns HandleResult
///
/// mint a new token
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `token_id` - optional token id, if not specified, use token index
/// * `owner` - optional owner of this token, if not specified, use the minter's address
/// * `public_metadata` - optional public metadata viewable by everyone
/// * `private_metadata` - optional private metadata viewable only by owner and whitelist
/// * `serial_number` - optional serial number information for this token
/// * `transferable` - optionally true if this token is transferable
#[allow(clippy::too_many_arguments)]
pub fn mint<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    owner: Option<HumanAddr>,
    // transferable: Option<bool>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let minters: Vec<CanonicalAddr> = may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_default();
    if !minters.contains(&sender_raw) {
        return Err(StdError::generic_err(
            "Only designated minters are allowed to mint",
        ));
    }
    let mints = vec![Mint {
        owner,
        // transferable,
    }];
    let mut minted = mint_list(deps, &env, config, &sender_raw, mints)?;
    let minted_str = minted.pop().unwrap_or_default();
    Ok(HandleResponse {
        messages: vec![],
        log: vec![log("minted", &minted_str)],
        data: Some(to_binary(&HandleAnswer::MintNft {
            // token_id: minted_str,
        })?),
    })
}

/// Returns HandleResult
///
/// mints many tokens
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `mints` - the list of mints to perform
pub fn batch_mint<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    mints: Vec<Mint>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let minters: Vec<CanonicalAddr> = may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_default();
    if !minters.contains(&sender_raw) {
        return Err(StdError::generic_err(
            "Only designated minters are allowed to mint",
        ));
    }
    let minted = mint_list(deps, &env, config, &sender_raw, mints)?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![log("minted", format!("{:?}", &minted))],
        data: Some(to_binary(&HandleAnswer::BatchMintNft {
            // token_ids: minted,
        })?),
    })
}

/// Returns HandleResult
///
/// mints clones of a token
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `mint_run_id` - optional id used to track subsequent mint runs
/// * `quantity` - number of clones to mint
/// * `owner` - optional owner of this token, if not specified, use the minter's address
/// * `public_metadata` - optional public metadata viewable by everyone
/// * `private_metadata` - optional private metadata viewable only by owner and whitelist
#[allow(clippy::too_many_arguments)]
pub fn mint_clones<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    quantity: u32,
    owner: Option<HumanAddr>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let minters: Vec<CanonicalAddr> = may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_default();
    if !minters.contains(&sender_raw) {
        return Err(StdError::generic_err(
            "Only designated minters are allowed to mint",
        ));
    }
    if quantity == 0 {
        return Err(StdError::generic_err("Quantity can not be zero"));
    }
    let mut mints: Vec<Mint> = Vec::new();
    for _ in 0..quantity {
        mints.push(Mint {
            owner: owner.clone(),
            // transferable: Some(true),
        });
    }
    let mut minted = mint_list(deps, &env, config, &sender_raw, mints)?;
    // if mint_list did not error, there must be at least one token id
    let first_minted = minted
        .first()
        .ok_or_else(|| StdError::generic_err("List of minted tokens is empty"))?
        .clone();
    let last_minted = minted
        .pop()
        .ok_or_else(|| StdError::generic_err("List of minted tokens is empty"))?;

    Ok(HandleResponse {
        messages: vec![],
        log: vec![
            log("first_minted", &first_minted),
            log("last_minted", &last_minted),
        ],
        data: Some(to_binary(&HandleAnswer::MintNftClones {
            first_minted,
            last_minted,
        })?),
    })
}

/// Returns HandleResult
///
/// sets new public and/or private metadata
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `token_id` - token id String slice of token whose metadata should be updated
/// * `public_metadata` - the optional new public metadata viewable by everyone
/// * `private_metadata` - the optional new private metadata viewable by everyone
pub fn set_metadata<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    public_metadata: Option<Metadata>,
    private_metadata: Option<Metadata>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let custom_err = format!("Not authorized to update metadata");
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they are not authorized for that token
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if !(config.admin == sender_raw) {
        return Err(StdError::generic_err(custom_err));
    }
    if let Some(public) = public_metadata {
        save(&mut deps.storage, PUBLIC_META_KEY, &public)?;
        // set_metadata_impl(&mut deps.storage, PREFIX_PUB_META, &public)?;
    }
    if let Some(private) = private_metadata {
        save(&mut deps.storage, PRIVATE_META_KEY, &private)?;
        // set_metadata_impl(&mut deps.storage, PREFIX_PRIV_META, &private)?;
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetMetadata { status: Success })?),
    })
}


/// Returns HandleResult
///
/// retrieves the metadata, public for every address, private if the address is privileged
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `token_id` - token id String slice of token whose metadata should be updated
/// * `public_metadata` - the optional new public metadata viewable by everyone
/// * `private_metadata` - the optional new private metadata viewable by everyone
pub fn retrieve_metadata<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
) -> HandleResult {
    check_status(config.status, priority)?;
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they are not authorized for that token
    // let config: Config = load(&deps.storage, CONFIG_KEY)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let owner_vec: Vec<CanonicalAddr> = load(&deps.storage, OWNERS_KEY)?;

    let public_metadata: Option<Metadata> = may_load(&deps.storage, PUBLIC_META_KEY)?;
    let mut private_metadata: Option<Metadata> = None;
    let mut display_private_metadata_error = None;
    if owner_vec.contains(&sender_raw) {
        private_metadata = may_load(&deps.storage, PRIVATE_META_KEY)?;
    } else {
        display_private_metadata_error = Some(
            "You are not authorized to retrieve private metadata".to_owned());
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::RetrieveMetadata {
            public_metadata: public_metadata,
            private_metadata: private_metadata,
            display_private_metadata_error: display_private_metadata_error,
        })?),
    })
}

/// Returns HandleResult
///
/// retrieves the owner list if a) the owner of the contract is the sender, or b) the owner list is public
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest status level this action is permitted at
/// * `token_id` - token id String slice of token whose metadata should be updated
/// * `public_metadata` - the optional new public metadata viewable by everyone
/// * `private_metadata` - the optional new private metadata viewable by everyone
pub fn retrieve_owners<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
) -> HandleResult {
    check_status(config.status, priority)?;

    let custom_err = format!("Not authorized to view owners");
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they are not authorized for that token
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;

    // Check if the owner list is public
    if !(config.owners_are_public || (config.admin == sender_raw)) {
        return Err(StdError::generic_err(custom_err));
    }
    let owner_vec: Vec<CanonicalAddr> = load(&deps.storage, OWNERS_KEY)?;
    let mut human_readable_owner_vec: Vec<HumanAddr> = Vec::new();
    for owner in owner_vec.into_iter() {
        human_readable_owner_vec.push(deps.api.human_address(&owner)?);
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::RetrieveOwners {
            owners: human_readable_owner_vec,
        })?),
    })
}

/// Returns StdResult<()>
///
/// sets new metadata  (so this is only called on instantiation of the contract)?  maybe not?
///
/// # Arguments
///
/// * `storage` - a mutable reference to the contract's storage
/// * `token` - a reference to the token whose metadata should be updated
/// * `idx` - the token identifier index
/// * `prefix` - storage prefix for the type of metadata being updated
/// * `metadata` - a reference to the new metadata
// #[allow(clippy::too_many_arguments)]
// fn set_metadata_impl<S: Storage>(
//     storage: &mut S,
//     prefix: &[u8],
//     metadata: &Metadata,
// ) -> StdResult<()> {
//     let mut meta_store = PrefixedStorage::new(prefix, storage);  // still use a prefix for public and private
//     // save(&mut meta_store, &idx.to_le_bytes(), metadata)?;
//     save(storage, )
//     save(&mut meta_store, CONTRACT_STORAGE_KEY, &metadata)?;
//     Ok(())
// }

/// Returns HandleResult
///
/// transfer many tokens
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `transfers` - list of transfers to perform
pub fn batch_transfer_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    transfers: Vec<Transfer>,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let _m = send_list(deps, &env, config, &sender_raw, Some(transfers))?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::BatchTransferNft {
            status: Success,
        })?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// transfer a token
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `recipient` - the address receiving the token
/// * `token_id` - token id String of token to be transferred
pub fn transfer_nft<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    recipient: HumanAddr,
    // token_id: String,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    let transfers = Some(vec![Transfer {
        recipient,
        // token_ids: vec![token_id],
    }]);
    let _m = send_list(deps, &env, config, &sender_raw, transfers)?;

    let res = HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::TransferNft { status: Success })?),
    };
    Ok(res)
}

/// Returns HandleResult
///
/// creates a viewing key
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `entropy` - string slice of the input String to be used as entropy in randomization
pub fn create_key<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &Config,
    priority: u8,
    entropy: &str,
) -> HandleResult {
    check_status(config.status, priority)?;
    let prng_seed: Vec<u8> = load(&deps.storage, PRNG_SEED_KEY)?;
    let key = ViewingKey::new(&env, &prng_seed, entropy.as_ref());
    let message_sender = deps.api.canonical_address(&env.message.sender)?;
    let mut key_store = PrefixedStorage::new(PREFIX_VIEW_KEY, &mut deps.storage);
    save(&mut key_store, message_sender.as_slice(), &key.to_hashed())?;
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ViewingKey {
            key: format!("{}", key),
        })?),
    })
}

/// Returns HandleResult
///
/// change the admin address
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `priority` - u8 representation of highest ContractStatus level this action is permitted
/// * `address` - new admin address
pub fn change_admin<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    priority: u8,
    address: &HumanAddr,
) -> HandleResult {
    check_status(config.status, priority)?;
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if config.admin != sender_raw {
        return Err(StdError::generic_err(
            "This is an admin command and can only be run from the admin address",
        ));
    }
    let new_admin = deps.api.canonical_address(address)?;
    let minters = vec![new_admin.clone()];
    if new_admin != config.admin {
        save(&mut deps.storage, MINTERS_KEY, &minters)?;
        config.admin = new_admin;
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::ChangeAdmin { status: Success })?),
    })
}

/////////////////////////////////////// Query /////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/// Returns QueryResult
///
/// # Arguments
///
/// * `deps` - reference to Extern containing all the contract's external dependencies
/// * `msg` - QueryMsg passed in with the query call
pub fn query<S: Storage, A: Api, Q: Querier>(deps: &Extern<S, A, Q>, msg: QueryMsg) -> QueryResult {
    let response = match msg {
        QueryMsg::ContractConfig {} => query_config(&deps.storage),
        QueryMsg::NumTokens { viewer } => query_num_tokens(deps, viewer),
        QueryMsg::NftDossier {
            viewer,
        } => query_nft_dossier(deps, viewer),
    };
    pad_query_result(response, BLOCK_SIZE)
}

/// Returns QueryResult displaying the contract's configuration
///
/// # Arguments
///
/// * `storage` - a reference to the contract's storage
pub fn query_config<S: ReadonlyStorage>(storage: &S) -> QueryResult {
    let config: Config = load(storage, CONFIG_KEY)?;

    to_binary(&QueryAnswer::ContractConfig {
        token_supply_is_public: config.token_supply_is_public,
        owners_are_public: config.owners_are_public,
        minter_may_update_metadata: config.minter_may_update_metadata,
        tokens_are_transferable: config.transferable,
    })
}

/// Returns QueryResult displaying the number of tokens the contract controls
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
pub fn query_num_tokens<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
) -> QueryResult {
    // authenticate permission to view token supply
    check_view_supply(deps, viewer)?;
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    to_binary(&QueryAnswer::NumTokens {
        count: config.token_cnt,
    })
}

/// Returns StdResult<()>
///
/// returns Ok if authorized to view token supply, Err otherwise
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `from_permit` - address derived from an Owner permit, if applicable
fn check_view_supply<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
) -> StdResult<()> {
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    let mut is_auth = config.token_supply_is_public;
    if !is_auth {
        let querier = get_querier(deps, viewer)?;
        if let Some(viewer_raw) = querier {
            let minters: Vec<CanonicalAddr> =
                may_load(&deps.storage, MINTERS_KEY)?.unwrap_or_default();
            is_auth = minters.contains(&viewer_raw);
        }
        if !is_auth {
            return Err(StdError::generic_err(
                "The token supply of this contract is private",
            ));
        }
    }
    Ok(())
}

/// Returns QueryResult displaying all the token information the querier is permitted to
/// view.  This may include the owner, the public metadata, the private metadata, royalty
/// information, mint run information, whether the token is unwrapped, whether the token is
/// transferable, and the token and inventory approvals
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `token_id` - the token id
/// * `viewer` - optional address and key making an authenticated query request
pub fn query_nft_dossier<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    // token_id: String,
    viewer: Option<ViewerInfo>,
) -> QueryResult {
    let dossier = dossier_list(deps, viewer)?
        .pop()
        .ok_or_else(|| {
            StdError::generic_err("NftDossier can never return an empty dossier list")
        })?;

    to_binary(&QueryAnswer::NftDossier {
        owner: dossier.contract_admin,
        public_metadata: dossier.public_metadata,
        private_metadata: dossier.private_metadata,
        // mint_run_info: dossier.mint_run_info,
        transferable: dossier.transferable,
        display_private_metadata_error: dossier.display_private_metadata_error,
        owners_are_public: dossier.owners_are_public,
    })
}

/// Returns StdResult<CanonicalAddr>
///
/// transfers a token, clears the token's permissions, and returns the previous owner's address
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `config` - a mutable reference to the Config
/// * `sender` - a reference to the message sender address
/// * `token_id` - token id String of token being transferred
/// * `recipient` - the recipient's address
/// * `inv_updates` - a mutable reference to the list of token inventories to update
#[allow(clippy::too_many_arguments)]
fn transfer_impl<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    config: &mut Config,
    sender: &CanonicalAddr,
    // token_id: String,
    recipient: CanonicalAddr,
    // inv_updates: &mut Vec<InventoryUpdate>,
) -> StdResult<CanonicalAddr> {
    // let (mut token, idx) = get_token_if_permitted(
    //     deps,
    //     &token_id,
    //     Some(sender),
    //     config,
    // )?;
    if !config.transferable {
        return Err(StdError::generic_err(
            "Tokens are non-transferable"
        ));
    }
    // let old_owner = token.owner;
    // // throw error if ownership would not change
    // if old_owner == recipient {
    //     return Err(StdError::generic_err(format!(
    //         "Attempting to transfer token ID: {} to the address that already owns it",
    //         &token_id
    //     )));
    // }
    // token.owner = recipient.clone();

    // just change the owner list by removing one instance of the owner
    let old_owner = sender;
    let old_owner_raw = (*old_owner).clone();
    let owner_vec: Vec<CanonicalAddr> = load(&deps.storage, OWNERS_KEY)?;
    if !(owner_vec.contains(old_owner)) {
        // throw an error
        return Err(StdError::generic_err(
            "Attempting to transfer token when you don't have one."
        ));
    } else {
        // remove one instance of owner
        let mut changed_flag = false;
        let mut new_owner_vec: Vec<CanonicalAddr> = Vec::new();

        for other_owner in owner_vec.into_iter() {
            if (other_owner == old_owner_raw) && !changed_flag {
                changed_flag = true;
                new_owner_vec.push(recipient.clone());
            } else {
                new_owner_vec.push(other_owner);
            }
        }
        // save the new owner vec
        save(&mut deps.storage, OWNERS_KEY, &new_owner_vec)?;
    } 
    // let update_addrs = vec![recipient.clone(), old_owner.clone()];
    // // save updated token info
    // let mut info_store = PrefixedStorage::new(PREFIX_INFOS, &mut deps.storage);
    // json_save(&mut info_store, &idx.to_le_bytes(), &token)?;
    // // log the inventory changes
    // for addr in update_addrs.into_iter() {
    //     let inv_upd = if let Some(inv) = inv_updates.iter_mut().find(|i| i.inventory.owner == addr)
    //     {
    //         inv
    //     } else {
    //         let inventory = Inventory::new(&deps.storage, addr)?;
    //         let new_inv = InventoryUpdate {
    //             inventory,
    //             remove: HashSet::new(),
    //         };
    //         inv_updates.push(new_inv);
    //         inv_updates.last_mut().ok_or_else(|| {
    //             StdError::generic_err("Just pushed an InventoryUpdate so this can not happen")
    //         })?
    //     };
    //     // if updating the recipient's inventory
    //     if inv_upd.inventory.owner == recipient {
    //         inv_upd.inventory.insert(&mut deps.storage, idx, false)?;
    //     // else updating the old owner's inventory
    //     } else {
    //         inv_upd.inventory.remove(&mut deps.storage, idx, false)?;
    //         inv_upd.remove.insert(idx);
    //     }
    // }
    
    Ok(old_owner_raw)
}

// list of tokens sent from one previous owner
pub struct SendFrom {
    // the owner's address
    pub owner: HumanAddr,
    // the tokens that were sent
    // pub token_ids: Vec<String>,
}

/// Returns StdResult<Vec<CosmosMsg>>
///
/// transfer or sends a list of tokens and returns a list of ReceiveNft callbacks if applicable
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `env` - a reference to the Env of the contract's environment
/// * `config` - a mutable reference to the Config
/// * `sender` - a reference to the message sender address
/// * `transfers` - optional list of transfers to perform
/// * `sends` - optional list of sends to perform
fn send_list<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: &Env,
    config: &mut Config,
    sender: &CanonicalAddr,
    transfers: Option<Vec<Transfer>>,
) -> StdResult<Vec<CosmosMsg>> {
    let messages: Vec<CosmosMsg> = Vec::new();
    // let mut inv_updates: Vec<InventoryUpdate> = Vec::new();
    if let Some(xfers) = transfers {
        for xfer in xfers.into_iter() {
            let recipient_raw = deps.api.canonical_address(&xfer.recipient)?;
            // for token_id in xfer.token_ids.into_iter() {
            let _o = transfer_impl(
                deps,
                config,
                sender,
                // token_id,
                recipient_raw.clone(),
                // &mut inv_updates,
            )?;
        }
    }
    save(&mut deps.storage, CONFIG_KEY, &config)?;
    // update_owner_inventory(&mut deps.storage, &inv_updates)?;
    Ok(messages)
}

/// Returns <Vec<String>>
///
/// mints a list of new tokens and returns the ids of the tokens minted
///
/// # Arguments
///
/// * `deps` - a mutable reference to Extern containing all the contract's external dependencies
/// * `env` - a reference to the Env of the contract's environment
/// * `config` - a mutable reference to the Config
/// * `sender_raw` - a reference to the message sender address
/// * `mints` - list of mints to perform
fn mint_list<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    _env: &Env,
    config: &mut Config,
    sender_raw: &CanonicalAddr,
    mints: Vec<Mint>,
) -> StdResult<Vec<String>> {
    // let mut inventories: Vec<Inventory> = Vec::new();
    let mut minted: Vec<String> = Vec::new();
    for mint in mints.into_iter() {
        // let id = mint.token_id.unwrap_or(format!("{}", config.mint_cnt));
        let id = format!("{}", config.mint_cnt);  // not sure why we need to grant control over token id.  This way we know exactly what tokens have been minted without having to keep a list
        // // check if id already exists
        // let mut map2idx = PrefixedStorage::new(PREFIX_MAP_TO_INDEX, &mut deps.storage);
        // let may_exist: Option<u32> = may_load(&map2idx, id.as_bytes())?;
        // if may_exist.is_some() {
        //     return Err(StdError::generic_err(format!(
        //         "Token ID {} is already in use",
        //         id
        //     )));
        // }
        // increment token count
        config.token_cnt = config.token_cnt.checked_add(1).ok_or_else(|| {
            StdError::generic_err("Attempting to mint more tokens than the implementation limit")
        })?;
        // map new token id to its index
        // save(&mut map2idx, id.as_bytes(), &config.mint_cnt)?;
        let recipient = if let Some(o) = mint.owner {
            deps.api.canonical_address(&o)?
        } else {
            sender_raw.clone()
        };
        // let transferable = mint.transferable.unwrap_or(true);
        // let token = Token {
        //     owner: recipient.clone(),
        //     transferable,
        // };

        // save new token info
        // let token_key = config.mint_cnt.to_le_bytes();
        // let mut info_store = PrefixedStorage::new(PREFIX_INFOS, &mut deps.storage);
        // json_save(&mut info_store, &token_key, &token)?;
        // add token to owner's list
        // let inventory = if let Some(inv) = inventories.iter_mut().find(|i| i.owner == token.owner) {
        //     inv
        // } else {
        //     let new_inv = Inventory::new(&deps.storage, token.owner.clone())?;
        //     inventories.push(new_inv);
        //     inventories.last_mut().ok_or_else(|| {
        //         StdError::generic_err("Just pushed an Inventory so this can not happen")
        //     })?
        // };
        // inventory.insert(&mut deps.storage, config.mint_cnt, false)?;

        // map index to id
        // let mut map2id = PrefixedStorage::new(PREFIX_MAP_TO_ID, &mut deps.storage);
        // save(&mut map2id, &token_key, &id)?;

        // add to the owner list
        let mut owner_vec: Vec<CanonicalAddr> = load(&deps.storage, OWNERS_KEY)?;
        owner_vec.push(recipient);
        // save the new owner vec
        save(&mut deps.storage, OWNERS_KEY, &owner_vec)?;

        // // save the mint run info
        // let (mint_run, serial_number, quantity_minted_this_run) =
        //     if let Some(ser) = mint.serial_number {
        //         (
        //             ser.mint_run,
        //             Some(ser.serial_number),
        //             ser.quantity_minted_this_run,
        //         )
        //     } else {
        //         (None, None, None)
        //     };
        // let mint_info = StoredMintRunInfo {
        //     token_creator: sender_raw.clone(),
        //     time_of_minting: env.block.time,
        //     mint_run,
        //     serial_number,
        //     quantity_minted_this_run,
        // };
        // let mut run_store = PrefixedStorage::new(PREFIX_MINT_RUN, &mut deps.storage);
        // save(&mut run_store, &token_key, &mint_info)?;

        minted.push(id);
        // increment index for next mint
        // config.mint_cnt = config.mint_cnt.checked_add(1).ok_or_else(|| {
        //     StdError::generic_err("Attempting to mint more times than the implementation limit")
        // })?;
    }
    // save all the updated inventories
    // for inventory in inventories.iter() {
    //     inventory.save(&mut deps.storage)?;
    // }
    save(&mut deps.storage, CONFIG_KEY, &config)?;
    Ok(minted)
}

/// Returns StdResult<()>
///
/// makes sure that Metadata does not have both `token_uri` and `extension`
///
/// # Arguments
///
/// * `metadata` - a reference to Metadata
// fn enforce_metadata_field_exclusion(metadata: &Metadata) -> StdResult<()> {
//     if metadata.token_uri.is_some() && metadata.extension.is_some() {
//         return Err(StdError::generic_err(
//             "Metadata can not have BOTH token_uri AND extension",
//         ));
//     }
//     Ok(())
// }

// used to cache owner information for dossier_list()
pub struct OwnerInfo {
    // the owner's address
    pub owner: CanonicalAddr,
    // the view_owner privacy override
    pub owners_are_public: bool,
}

/// Returns StdResult<()> that will error if the priority level of the action is not
/// equal to or greater than the current contract status level
///
/// # Arguments
///
/// * `contract_status` - u8 representation of the current contract status
/// * `priority` - u8 representing the highest status level this action may execute at
fn check_status(contract_status: u8, priority: u8) -> StdResult<()> {
    if priority < contract_status {
        return Err(StdError::generic_err(
            "The contract admin has temporarily disabled this action",
        ));
    }
    Ok(())
}

/// Returns HandleResult
///
/// set the contract status level
///
/// # Arguments
///
/// * `deps` - mutable reference to Extern containing all the contract's external dependencies
/// * `env` - Env of contract's environment
/// * `config` - a mutable reference to the Config
/// * `level` - new ContractStatus
pub fn set_contract_status<S: Storage, A: Api, Q: Querier>(
    deps: &mut Extern<S, A, Q>,
    env: Env,
    config: &mut Config,
    level: ContractStatus,
) -> HandleResult {
    let sender_raw = deps.api.canonical_address(&env.message.sender)?;
    if config.admin != sender_raw {
        return Err(StdError::generic_err(
            "This is an admin command and can only be run from the admin address",
        ));
    }
    let new_status = level.to_u8();
    if config.status != new_status {
        config.status = new_status;
        save(&mut deps.storage, CONFIG_KEY, &config)?;
    }
    Ok(HandleResponse {
        messages: vec![],
        log: vec![],
        data: Some(to_binary(&HandleAnswer::SetContractStatus {
            status: Success,
        })?),
    })
}


/// Returns StdResult<bool> result of validating an address' viewing key
///
/// # Arguments
///
/// * `storage` - a reference to the contract's storage
/// * `address` - a reference to the address whose key should be validated
/// * `viewing_key` - String key used for authentication
fn check_key<S: ReadonlyStorage>(
    storage: &S,
    address: &CanonicalAddr,
    viewing_key: String,
) -> StdResult<()> {
    // load the address' key
    let read_key = ReadonlyPrefixedStorage::new(PREFIX_VIEW_KEY, storage);
    let load_key: [u8; VIEWING_KEY_SIZE] =
        may_load(&read_key, address.as_slice())?.unwrap_or([0u8; VIEWING_KEY_SIZE]);
    let input_key = ViewingKey(viewing_key);
    // if key matches
    if input_key.check_viewing_key(&load_key) {
        return Ok(());
    }
    Err(StdError::generic_err(
        "Wrong viewing key for this address or viewing key not set",
    ))
}

/// Returns StdResult<Vec<BatchNftDossierElement>> of all the token information the querier is permitted to
/// view for multiple tokens.  This may include the owner, the public metadata, the private metadata, royalty
/// information, mint run information, whether the token is unwrapped, whether the token is
/// transferable, and the token and inventory approvals
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `token_ids` - list of token ids to retrieve the info of
/// * `viewer` - optional address and key making an authenticated query request
pub fn dossier_list<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    // token_ids: Vec<String>,
    viewer: Option<ViewerInfo>,
) -> StdResult<Vec<BatchNftDossierElement>> {
    let viewer_raw = get_querier(deps, viewer)?;
    let opt_viewer = viewer_raw.as_ref();
    let config: Config = load(&deps.storage, CONFIG_KEY)?;
    // let contract_creator = deps
    //     .api
    //     .human_address(&load::<CanonicalAddr, _>(&deps.storage, CREATOR_KEY)?)?;
    // used to shortcut permission checks if the viewer is already a known operator for a list of owners
    // let mut owner_cache: Vec<OwnerInfo> = Vec::new();
    let mut dossiers: Vec<BatchNftDossierElement> = Vec::new();
    // set up all the immutable storage references
    // let pub_store = ReadonlyPrefixedStorage::new(PREFIX_PUB_META, &deps.storage);
    // let priv_store = ReadonlyPrefixedStorage::new(PREFIX_PRIV_META, &deps.storage);
    // for id in token_ids.into_iter() {
    //     let err_msg = format!(
    //         "You are not authorized to perform this action on token {}",
    //         &id
    //     );
    let err_msg = "You are not authorized";
    // if token supply is private, don't leak that the token id does not exist
    // instead just say they are not authorized for that token
    // let opt_err = if config.token_supply_is_public {
    //     None
    // } else {
    //     Some(&*err_msg)
    // };

    //#$#$#$#$#$#$#$#$ load the owner list, and let that determine whether you reveal the private metadata
    // let owner_vec: Vec<CanonicalAddr> = load(&deps.storage, OWNERS_KEY)?;
    // // check that the viewer_raw is in the owner list
    // if let Some(opt_viewer) = opt_viewer_address {
    //     if owner_vec.contains(opt_viewer_address) {

    // } 

    // let (token, _idx) = get_token(&deps.storage, &id, opt_err)?;  // retrieves the Token struct from the state -- really just the owner and if it's transferable
    // let owner_slice = token.owner.as_slice();
    // get the owner info either from the cache or storage
    // let owner_inf = if let Some(inf) = owner_cache.iter().find(|o| o.owner == token.owner) {
    //     inf
    // } else {
    //     let owners_are_public: bool = config.owners_are_public;
    //     owner_cache.push(OwnerInfo {
    //         owner: token.owner.clone(),
    //         owners_are_public,
    //     });
    //     owner_cache.last().ok_or_else(|| {
    //         StdError::generic_err("This can't happen since we just pushed an OwnerInfo!")
    //     })?
    // };
    // let global_pass = owner_inf.owners_are_public;
    // get the owner if permitted
    // let owner = if global_pass
    //     || check_perm_core(
    //         deps,
    //         &token,
    //         opt_viewer,
    //         &err_msg,
    //     )
    //     .is_ok()
    // {
    //     Some(deps.api.human_address(&token.owner)?)
    // } else {
    //     None
    // };
    // get the public metadata
    // let token_key = idx.to_le_bytes();
    let public_metadata: Option<Metadata> = may_load(&deps.storage, PUBLIC_META_KEY)?;  // substantial change -- this does not care about the token id, just accesses the metadata shared across the contract
    // get the private metadata if it is not sealed and if the viewer is permitted
    let mut display_private_metadata_error = None;
    let private_metadata = if let Err(err) = check_perm_core(
        deps,
        // &token,
        opt_viewer,
        &err_msg,
    ) {
        if let StdError::GenericErr { msg, .. } = err {
            display_private_metadata_error = Some(msg);
        }
        None
    } else {
        let priv_meta: Option<Metadata> = may_load(&deps.storage, PRIVATE_META_KEY)?;
        priv_meta
    };
    // get the mint run information
    // let mint_run: StoredMintRunInfo = load(&run_store, &token_key)?;
    // let (token_approv, token_owner_exp, token_meta_exp) = gen_snip721_approvals(
    // determine if ownership is public
    let owners_are_public = config.owners_are_public;
    let contract_admin = Some(deps.api.human_address(&config.admin)?);
    dossiers.push(BatchNftDossierElement {
        contract_admin,
        public_metadata,
        private_metadata,
        // mint_run_info: Some(mint_run.to_human(&deps.api, contract_creator.clone())?),
        transferable: config.transferable,
        display_private_metadata_error,
        owners_are_public,
        });
    
    Ok(dossiers)
}

/// Returns StdResult<Option<CanonicalAddr>> from determining the querying address (if possible) either
/// from a permit validation or a ViewerInfo
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `viewer` - optional address and key making an authenticated query request
/// * `from_permit` - the address derived from an Owner permit, if applicable
fn get_querier<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    viewer: Option<ViewerInfo>,
) -> StdResult<Option<CanonicalAddr>> {
    let viewer_raw = viewer
        .map(|v| {
            let raw = deps.api.canonical_address(&v.address)?;
            check_key(&deps.storage, &raw, v.viewing_key)?;
            Ok(raw)
        })
        .transpose()?;
    Ok(viewer_raw)
}


/// Returns StdResult<()>
///
/// returns Ok if the address has permission or an error if not
///
/// # Arguments
///
/// * `deps` - a reference to Extern containing all the contract's external dependencies
/// * `token` - a reference to the token
/// * `token_id` - token ID String slice
/// * `opt_sender` - a optional reference to the address trying to get access to the token
/// * `exp_idx` - permission type we are checking represented as usize
/// * `custom_err` - string slice of the error msg to return if not permitted
#[allow(clippy::too_many_arguments)]
fn check_perm_core<S: Storage, A: Api, Q: Querier>(
    deps: &Extern<S, A, Q>,
    // token: &Token,
    opt_sender: Option<&CanonicalAddr>,
    custom_err: &str,
) -> StdResult<()> {
    let err_msg = custom_err;
    let global_raw = CanonicalAddr(Binary::from(b"public"));
    let (sender, _only_public) = if let Some(sdr) = opt_sender {
        (sdr, false)
    } else {
        (&global_raw, true)
    };

    // if this is the owner, all is good
    // if token.owner == *sender {
    let owner_vec: Vec<CanonicalAddr> = load(&deps.storage, OWNERS_KEY)?;
    if owner_vec.contains(sender) {
        return Ok(());
    } else {
        return Err(StdError::generic_err(err_msg));
    };
}