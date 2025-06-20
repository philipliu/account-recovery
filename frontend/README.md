# Smart Wallet with WebAuthn Recovery

A demo application showcasing a Stellar smart contract wallet secured by WebAuthn/passkeys with recovery functionality.

## Features

- **Biometric Authentication**: Create and access wallets using device biometrics (Face ID, Touch ID, Windows Hello, etc.)
- **Deterministic Addresses**: Wallet addresses are derived from your email/username, enabling access from any device
- **Recovery System**: Set up recovery signers to regain access if you lose your device
- **Passkey Rotation**: Switch to a new device by rotating your passkey using the recovery wallet

## How It Works

1. **Create Wallet**: Register a passkey and deploy a smart contract wallet to Stellar testnet
2. **Login**: Authenticate with your passkey to access your existing wallet
3. **Set Recovery**: Connect an external wallet (Freighter, etc.) as a recovery signer
4. **Rotate Passkey**: Use your recovery wallet to authorize switching to a new device/passkey

The wallet address is deterministically generated from your identifier, so you can access the same wallet from different devices by using the same email/username.

## Setup

1. **Install dependencies**:
   ```bash
   npm install
   ```

2. **Environment configuration**:
   This app loads environment variables from the parent directory's `.env` file. Make sure you have a `.env` file in the parent directory (`../`) with:
   ```
   DEPLOYER_SECRET=<your_stellar_secret_key>
   FACTORY_CONTRACT_ID=CCLN4GLYSIRHUY7Q4Q73TUJXQYD4COXDDFCYHKRGOZOZOTTTLXCX46KL
   ```
   
   Note: The `vite.config.ts` is configured to automatically map these to `VITE_` prefixed variables for browser access.

3. **Start development server**:
   ```bash
   npm run dev
   ```

## Requirements

- Modern browser with WebAuthn support
- Device with biometric authentication (recommended)
- Stellar wallet (Freighter, etc.) for recovery setup

## Factory Contract

This demo runs on Stellar testnet. The factory contract is pre-deployed at:
```
CCLN4GLYSIRHUY7Q4Q73TUJXQYD4COXDDFCYHKRGOZOZOTTTLXCX46KL
```
