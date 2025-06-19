#! /bin/bash

source .env
pushd contracts

stellar contract build

echo "Uploading smart wallet contract..."
SMART_WALLET_HASH=$(stellar contract upload \
  --source $DEPLOYER_SECRET \
  --wasm target/wasm32-unknown-unknown/release/smart_wallet.wasm)

echo "Smart wallet wasm hash: $SMART_WALLET_HASH"

echo "Deploying factory contract..."
FACTORY_ADDRESS=$(stellar contract deploy \
  --source $DEPLOYER_SECRET \
  --wasm target/wasm32-unknown-unknown/release/factory.wasm \
  -- \
  --wasm-hash $SMART_WALLET_HASH)

echo "Factory contract deployed at: $FACTORY_ADDRESS"

popd
