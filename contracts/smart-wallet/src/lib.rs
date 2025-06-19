#![no_std]

use soroban_sdk::{
    auth::{Context, CustomAccountInterface},
    contract, contracterror, contractimpl, contracttype,
    crypto::Hash,
    Address, BytesN, Env, Vec,
};

mod base64_url;
mod webauthn;

#[derive(Clone, Debug, PartialEq, PartialOrd)]
#[contracttype]
pub enum DataKey {
    Admin,
    RecoveryAddress,
    Signer,
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
#[contracterror]
pub enum AccountContractError {
    MissingSigner = 1,
    WebAuthnInvalidClientData = 1001,
    WebAuthnInvalidType = 1002,
    WebAuthnUserNotPresent = 1003,
    WebAuthnUserNotVerified = 1004,
    WebAuthnInvalidChallenge = 1005,
}

#[contract]
pub struct AccountContract;

#[contractimpl]
impl AccountContract {
    pub fn __constructor(env: Env, admin: Address, public_key: BytesN<65>) {
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::Signer, &public_key);
    }

    pub fn upgrade(env: Env, new_wasm_hash: BytesN<32>) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        admin.require_auth();

        env.deployer().update_current_contract_wasm(new_wasm_hash);
    }
}

#[derive(Clone, Debug, PartialEq, PartialOrd)]
#[contracterror]
pub enum RecoveryError {
    MissingSigner = 2000,
    InvalidNewSigner = 2001,
    MissingRecovery = 2002,
    RecoveryAlreadySet = 2003,
}

pub trait Recovery {
    fn recovery(env: Env) -> Option<Address>;
    fn set_recovery(env: Env, recovery_address: Address) -> Result<(), RecoveryError>;
    fn rotate_signer(env: Env, new_signer: BytesN<65>) -> Result<(), RecoveryError>;
}

#[contractimpl]
impl Recovery for AccountContract {
    fn recovery(env: Env) -> Option<Address>{
        env.storage()
            .instance()
            .get(&DataKey::RecoveryAddress)
    }

    fn set_recovery(env: Env, recovery_address: Address) -> Result<(), RecoveryError> {
        if let Some(_) = env.storage().instance().get::<_, Address>(&DataKey::RecoveryAddress) {
            return Err(RecoveryError::RecoveryAlreadySet);
        }
        env.current_contract_address().require_auth();

        env.storage()
            .instance()
            .set(&DataKey::RecoveryAddress, &recovery_address);
        Ok(())
    }

    fn rotate_signer(env: Env, new_signer: BytesN<65>) -> Result<(), RecoveryError> {
        let recovery: Address = env
            .storage()
            .instance()
            .get(&DataKey::RecoveryAddress)
            .ok_or(RecoveryError::MissingRecovery)?;
        recovery.require_auth();

        let current_signer: BytesN<65> = env
            .storage()
            .instance()
            .get(&DataKey::Signer)
            .ok_or(RecoveryError::MissingSigner)?;

        if current_signer == new_signer {
            return Err(RecoveryError::InvalidNewSigner);
        }

        env.storage().instance().set(&DataKey::Signer, &new_signer);
        Ok(())
    }
}

#[contractimpl]
impl CustomAccountInterface for AccountContract {
    type Error = AccountContractError;
    type Signature = webauthn::WebAuthnCredential;

    fn __check_auth(
        env: Env,
        signature_payload: Hash<32>,
        signatures: Self::Signature,
        _auth_contexts: Vec<Context>,
    ) -> Result<(), Self::Error> {
        let public_key = env
            .storage()
            .instance()
            .get::<_, BytesN<65>>(&DataKey::Signer)
            .ok_or(AccountContractError::MissingSigner)?;

        webauthn::verify(&env, &signature_payload, &signatures, &public_key);

        Ok(())
    }
}

mod test;
