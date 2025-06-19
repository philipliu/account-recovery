#![no_std]

use soroban_sdk::{
    contract, contracterror, contractimpl, symbol_short, Address, BytesN, Env, Symbol,
};

#[contract]
pub struct FactoryContract;

#[contracterror]
pub enum FactoryError {
    InvalidWasmHash = 1000,
}

const WASM_HASH_KEY: Symbol = symbol_short!("hash");

#[contractimpl]
impl FactoryContract {
    pub fn __constructor(env: Env, wasm_hash: BytesN<32>) {
        env.storage().instance().set(&WASM_HASH_KEY, &wasm_hash);
    }

    pub fn deploy(
        env: Env,
        salt: BytesN<32>,
        admin: Address,
        public_key: BytesN<65>,
    ) -> Result<Address, FactoryError> {
        // TODO: only admin should be able to deploy
        let wasm_hash: BytesN<32> = env
            .storage()
            .instance()
            .get(&WASM_HASH_KEY)
            .ok_or(FactoryError::InvalidWasmHash)?;
        let address = env
            .deployer()
            .with_current_contract(salt)
            .deploy_v2(wasm_hash, (admin, public_key));
        Ok(address)
    }
}
