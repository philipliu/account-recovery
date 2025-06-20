import { useState } from "react";
import {
  startAuthentication,
  startRegistration,
} from "@simplewebauthn/browser";
import type { AuthenticatorAttestationResponseJSON } from "@simplewebauthn/types";
import base64url from "base64url";
import {
  Address,
  Contract,
  hash,
  Keypair,
  nativeToScVal,
  Networks,
  rpc,
  scValToNative,
  StrKey,
  TransactionBuilder,
  xdr,
} from "@stellar/stellar-sdk";
import {
  allowAllModules,
  StellarWalletsKit,
  WalletNetwork,
} from "@creit.tech/stellar-wallets-kit";
import "./App.css";

const FACTORY_CONTRACT_ID =
  "CCLN4GLYSIRHUY7Q4Q73TUJXQYD4COXDDFCYHKRGOZOZOTTTLXCX46KL";
const NETWORK_PASSPHRASE = Networks.TESTNET;
const RPC_URL = "https://soroban-testnet.stellar.org";

function App() {
  const [status, setStatus] = useState<string>("");
  const [walletAddress, setWalletAddress] = useState<string>("");
  const [publicKey, setPublicKey] = useState<string>("");
  const [credentialId, setCredentialId] = useState<string>("");
  const [isDeploying, setIsDeploying] = useState(false);
  const [isLoggedIn, setIsLoggedIn] = useState(false);
  const [loginPublicKey, setLoginPublicKey] = useState<string>("");
  const [loginWalletAddress, setLoginWalletAddress] = useState<string>("");
  const [userIdentifier, setUserIdentifier] = useState<string>("");
  const [recoveryAddress, setRecoveryAddress] = useState<string>("");
  const [isSettingRecovery, setIsSettingRecovery] = useState(false);
  const [isRotatingSigner, setIsRotatingSigner] = useState(false);
  const [newPasskeyDisplayName, setNewPasskeyDisplayName] = useState<string>(
    "",
  );
  const [walletKit, setWalletKit] = useState<StellarWalletsKit | null>(null);
  const [loginIdentifier, setLoginIdentifier] = useState<string>("");
  const [showLoginFallback, setShowLoginFallback] = useState(false);
  const [currentRecoveryAddress, setCurrentRecoveryAddress] = useState<string>(
    "",
  );
  const [shouldFlashCredentialId, setShouldFlashCredentialId] = useState(false);
  const [showTxModal, setShowTxModal] = useState(false);
  const [txSimulation, setTxSimulation] = useState<any>(null);

  const extractPublicKey = (
    response: AuthenticatorAttestationResponseJSON,
  ): Uint8Array | null => {
    // Try to extract public key from different response formats

    // Method 1: Direct publicKey field
    if (response.publicKey) {
      const publicKeyBuffer = base64url.toBuffer(response.publicKey);
      // Check if it's already in the right format
      if (publicKeyBuffer.length === 65 && publicKeyBuffer[0] === 0x04) {
        return new Uint8Array(publicKeyBuffer);
      }
      // If it's DER encoded, extract the raw key
      if (publicKeyBuffer.length > 65) {
        for (let i = publicKeyBuffer.length - 65; i >= 0; i--) {
          if (publicKeyBuffer[i] === 0x04 && i + 65 <= publicKeyBuffer.length) {
            return new Uint8Array(publicKeyBuffer.slice(i, i + 65));
          }
        }
      }
    }

    // Method 2: Parse from attestationObject
    if (response.attestationObject) {
      const attestationObject = base64url.toBuffer(response.attestationObject);

      // Search for COSE key structure
      // Looking for the x and y coordinates in CBOR format
      for (let i = 0; i < attestationObject.length - 70; i++) {
        if (
          attestationObject[i] === 0x21 && // -2 (x coordinate key)
          attestationObject[i + 1] === 0x58 && // byte string
          attestationObject[i + 2] === 0x20 && // length 32
          i + 35 < attestationObject.length &&
          attestationObject[i + 35] === 0x22 && // -3 (y coordinate key)
          attestationObject[i + 36] === 0x58 && // byte string
          attestationObject[i + 37] === 0x20
        ) { // length 32
          const x = attestationObject.slice(i + 3, i + 35);
          const y = attestationObject.slice(i + 38, i + 70);

          // Create uncompressed public key
          const publicKey = new Uint8Array(65);
          publicKey[0] = 0x04;
          publicKey.set(x, 1);
          publicKey.set(y, 33);
          return publicKey;
        }
      }
    }

    // Method 3: Parse from authenticatorData if available
    if (response.authenticatorData) {
      const authData = base64url.toBuffer(response.authenticatorData);

      // Skip RP ID hash (32) + flags (1) + counter (4) = 37 bytes
      // Check if credential data is present (bit 6 of flags byte)
      if (authData.length > 37 && (authData[32] & 0x40)) {
        let offset = 37;

        // Skip AAGUID (16 bytes)
        offset += 16;

        // Get credential ID length (2 bytes, big-endian)
        if (offset + 2 <= authData.length) {
          const credIdLen = (authData[offset] << 8) | authData[offset + 1];
          offset += 2 + credIdLen;

          // Now we should be at the public key in COSE format
          // Search for x and y coordinates
          for (
            let i = offset; i < authData.length - 70 && i < offset + 200; i++
          ) {
            if (
              authData[i] === 0x21 && authData[i + 1] === 0x58 &&
              authData[i + 2] === 0x20 &&
              i + 35 < authData.length &&
              authData[i + 35] === 0x22 && authData[i + 36] === 0x58 &&
              authData[i + 37] === 0x20
            ) {
              const x = authData.slice(i + 3, i + 35);
              const y = authData.slice(i + 38, i + 70);

              const publicKey = new Uint8Array(65);
              publicKey[0] = 0x04;
              publicKey.set(x, 1);
              publicKey.set(y, 33);
              return publicKey;
            }
          }
        }
      }
    }

    return null;
  };

  const computeWalletAddress = (identifier: string): string => {
    try {
      // Use user identifier as salt (truncated/padded to 32 bytes)
      const saltBytes = new Uint8Array(32);
      const identifierBytes = new TextEncoder().encode(
        identifier.toLowerCase().trim(),
      );
      saltBytes.set(
        identifierBytes.slice(0, Math.min(32, identifierBytes.length)),
      );

      // Use the exact hashIdPreimage technique from SEP smart wallet
      // https://github.com/stellar/sep-smart-wallet/blob/main/src/services/SorobanService.ts#L263-L281

      const preimage = xdr.HashIdPreimage.envelopeTypeContractId(
        new xdr.HashIdPreimageContractId({
          networkId: hash(Buffer.from(NETWORK_PASSPHRASE, "utf8")),
          contractIdPreimage: xdr.ContractIdPreimage
            .contractIdPreimageFromAddress(
              new xdr.ContractIdPreimageFromAddress({
                address: Address.fromString(FACTORY_CONTRACT_ID).toScAddress(),
                salt: hash(Buffer.from(saltBytes)),
              }),
            ),
        }),
      );

      return StrKey.encodeContract(hash(preimage.toXDR()));
    } catch (error) {
      console.error("Error computing wallet address:", error);
      return "Error computing address";
    }
  };

  const handleRegisterAndDeploy = async () => {
    if (!userIdentifier.trim()) {
      setStatus("Please enter a user identifier (email/username)");
      return;
    }

    try {
      setIsDeploying(true);
      setStatus("Starting WebAuthn registration...");

      const registration = await startRegistration({
        optionsJSON: {
          challenge: base64url("stellaristhebetterblockchain"),
          rp: {
            name: "Smart Wallet Demo",
            id: window.location.hostname,
          },
          user: {
            id: base64url(userIdentifier.toLowerCase().trim()), // Store identifier in userHandle for retrieval
            name: userIdentifier.toLowerCase().trim(), // Use original identifier for name
            displayName: userIdentifier.trim(), // Use original identifier for display
          },
          pubKeyCredParams: [{ alg: -7, type: "public-key" }], // ES256
          authenticatorSelection: {
            authenticatorAttachment: "platform",
            residentKey: "preferred",
            userVerification: "required",
          },
          attestation: "none",
        },
      });

      console.log("Registration response:", registration);

      const publicKeyBytes = extractPublicKey(registration.response);

      if (!publicKeyBytes) {
        throw new Error("Failed to extract public key from response");
      }

      const publicKeyHex = Array.from(publicKeyBytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      console.log("Extracted public key:", publicKeyHex);

      setPublicKey(publicKeyHex);
      setCredentialId(registration.id);
      setStatus(
        "WebAuthn registration successful! Now deploying smart wallet...",
      );

      // Immediately deploy the wallet using the credential ID
      await deployWalletWithCredentials(registration.id, publicKeyHex);
    } catch (error) {
      console.error("Registration and deployment error:", error);
      setStatus(`Registration/deployment failed: ${error}`);
      setIsDeploying(false);
    }
  };

  const deployWalletWithCredentials = async (
    _credId: string,
    pubKey: string,
  ) => {
    try {
      // Use deployer account from environment variable
      const deployerSecret = import.meta.env.VITE_DEPLOYER_SECRET;
      if (!deployerSecret) {
        throw new Error("VITE_DEPLOYER_SECRET not set in environment");
      }

      // Use deployer as admin so we can perform recovery operations later
      // In production, this should be a dedicated admin key
      const adminKeypair = Keypair.fromSecret(deployerSecret);

      // Use user identifier as salt for deterministic address derivation
      // This must match the salt used in computeWalletAddress
      const saltBytes = new Uint8Array(32);
      const identifierBytes = new TextEncoder().encode(
        userIdentifier.toLowerCase().trim(),
      );
      saltBytes.set(
        identifierBytes.slice(0, Math.min(32, identifierBytes.length)),
      );

      // Hash the salt bytes just like in computeWalletAddress
      const hashedSalt = hash(Buffer.from(saltBytes));

      // Compute the expected wallet address
      const expectedAddress = computeWalletAddress(userIdentifier);
      console.log("Expected wallet address:", expectedAddress);

      // Create Soroban RPC client
      const server = new rpc.Server(RPC_URL);

      const sourceKeypair = adminKeypair;
      setStatus("Fetching deployer account...");

      const sourceAccount = await server.getAccount(sourceKeypair.publicKey());

      // Build the transaction to call the factory deploy method
      const contract = new Contract(FACTORY_CONTRACT_ID);

      const transaction = new TransactionBuilder(sourceAccount, {
        fee: "100000",
        networkPassphrase: NETWORK_PASSPHRASE,
      })
        .addOperation(
          contract.call(
            "deploy",
            nativeToScVal(hashedSalt, { type: "bytes" }),
            Address.fromString(adminKeypair.publicKey()).toScVal(),
            nativeToScVal(
              Uint8Array.from(pubKey.match(/.{1,2}/g)!.map((byte) =>
                parseInt(byte, 16)
              )),
              { type: "bytes" },
            ),
          ),
        )
        .setTimeout(30)
        .build();

      // Simulate the transaction
      const simulatedTx = await server.simulateTransaction(transaction);

      if ("error" in simulatedTx) {
        throw new Error(`Simulation failed: ${simulatedTx.error}`);
      }

      // Prepare and submit the transaction
      const preparedTx = await server.prepareTransaction(transaction);
      preparedTx.sign(sourceKeypair);

      const result = await server.sendTransaction(preparedTx);

      if (result.status === "PENDING") {
        // Wait for transaction confirmation
        const hash = result.hash;
        let getResponse = await server.getTransaction(hash);

        while (getResponse.status === "NOT_FOUND") {
          await new Promise((resolve) => setTimeout(resolve, 1000));
          getResponse = await server.getTransaction(hash);
        }

        if (getResponse.status === "SUCCESS") {
          // Extract the deployed contract address from the result
          const returnValue = getResponse.returnValue;
          if (returnValue) {
            const address = scValToNative(returnValue);
            setWalletAddress(address);

            // Verify that the deployed address matches our computation
            const matches = address === expectedAddress;
            setStatus(
              `Smart wallet created and deployed successfully! ${
                matches ? "✓" : "✗"
              } Address matches computation`,
            );

            if (!matches) {
              console.warn("Address mismatch:", {
                deployed: address,
                expected: expectedAddress,
              });
            }
          }
        } else {
          throw new Error("Transaction failed");
        }
      }
    } catch (error) {
      console.error("Deployment error:", error);
      setStatus(`Deployment failed: ${error}`);
      throw error;
    } finally {
      setIsDeploying(false);
    }
  };

  const fetchRecoveryAddress = async (walletAddress: string) => {
    try {
      console.log("Fetching recovery address for wallet:", walletAddress);

      const contract = new Contract(walletAddress);
      const rpcServer = new rpc.Server(RPC_URL);
      const sourceAccount = await rpcServer.getAccount(
        Keypair.fromSecret(import.meta.env.VITE_DEPLOYER_SECRET).publicKey(),
      );
      const recoveryCall = contract.call("recovery");
      const recoveryResult = await rpcServer.simulateTransaction(
        new TransactionBuilder(sourceAccount, {
          fee: "100",
          networkPassphrase: NETWORK_PASSPHRASE,
        })
          .addOperation(recoveryCall)
          .setTimeout(300)
          .build(),
      );

      if ("result" in recoveryResult && recoveryResult.result) {
        const recoveryAddressFromContract = scValToNative(
          recoveryResult.result.retval,
        );
        console.log(
          "Recovery address from contract:",
          recoveryAddressFromContract,
        );
        setCurrentRecoveryAddress(recoveryAddressFromContract);
        return recoveryAddressFromContract;
      } else {
        console.log("No recovery address set");
        setCurrentRecoveryAddress("");
        return null;
      }
    } catch (error) {
      console.log("Error fetching recovery address:", error);
      setCurrentRecoveryAddress("");
      return null;
    }
  };

  const extractUsernameFromPasskey = (authentication: any): string | null => {
    try {
      // Try to get username from userHandle if available
      if (authentication.response.userHandle) {
        const userHandle = base64url.toBuffer(
          authentication.response.userHandle,
        );
        const decoded = new TextDecoder().decode(userHandle);
        console.log("Extracted userHandle:", decoded);
        return decoded;
      }

      // Some browsers store the username in different locations
      // This is browser-dependent and may not always be available
      console.log("No userHandle found in passkey response");
      return null;
    } catch (error) {
      console.log("Failed to extract username from passkey:", error);
      return null;
    }
  };

  const handleLoginWithPasskey = async () => {
    try {
      setStatus("Starting WebAuthn authentication...");

      const challenge = base64url("login-challenge-" + Date.now());

      const authentication = await startAuthentication({
        optionsJSON: {
          challenge,
          rpId: window.location.hostname,
          userVerification: "required",
        },
      });

      console.log("Authentication response:", authentication);

      // Try to extract username from the passkey
      const extractedUsername = extractUsernameFromPasskey(authentication);

      if (extractedUsername) {
        // Success! We got the username from the passkey
        await completeLogin(authentication, extractedUsername);
      } else {
        // Fallback: ask user to enter their identifier
        setCredentialId(authentication.id);
        setShowLoginFallback(true);
        setStatus(
          "Please enter the identifier you used to create this wallet:",
        );
      }
    } catch (error) {
      console.error("Authentication error:", error);
      setStatus(`Login failed: ${error}`);
    }
  };

  const handleLoginFallback = async () => {
    if (!loginIdentifier.trim()) {
      setStatus("Please enter your identifier (email/username)");
      return;
    }

    // We already have the authentication from the previous step
    const computedWalletAddress = computeWalletAddress(loginIdentifier);
    setLoginWalletAddress(computedWalletAddress);
    setIsLoggedIn(true);
    setShowLoginFallback(false);

    // Check if this matches our session credentials
    if (credentialId === credentialId && publicKey) {
      setLoginPublicKey(publicKey);
      setStatus(
        `Login successful! Connected to wallet: ${computedWalletAddress}`,
      );
    } else {
      setLoginPublicKey("(Would extract from credential)");
      setStatus(
        `Login successful! Computed wallet address: ${computedWalletAddress}`,
      );
    }

    console.log("Login completed with fallback identifier:", {
      credentialId,
      identifier: loginIdentifier,
      walletAddress: computedWalletAddress,
    });
  };

  const completeLogin = async (authentication: any, identifier: string) => {
    // Extract the signature and authenticator data
    const clientDataJSON = base64url.toBuffer(
      authentication.response.clientDataJSON,
    );
    const authenticatorData = base64url.toBuffer(
      authentication.response.authenticatorData,
    );
    const signature = base64url.toBuffer(authentication.response.signature);

    // Store the authentication data
    setCredentialId(authentication.id);
    setLoginIdentifier(identifier);

    // Compute the deterministic wallet address using the extracted identifier
    const computedWalletAddress = computeWalletAddress(identifier);

    setLoginWalletAddress(computedWalletAddress);
    setIsLoggedIn(true);

    // Fetch the current recovery address for this wallet
    await fetchRecoveryAddress(computedWalletAddress);

    // Check if this matches our session credentials
    if (authentication.id === credentialId && publicKey) {
      setLoginPublicKey(publicKey);
      setStatus(
        `Login successful! Connected to wallet: ${computedWalletAddress}`,
      );
    } else {
      setLoginPublicKey("(Would extract from credential)");
      setStatus(
        `Login successful! Connected to wallet: ${computedWalletAddress}`,
      );
    }

    console.log("Authentication successful:", {
      credentialId: authentication.id,
      identifier,
      walletAddress: computedWalletAddress,
      clientDataJSON: base64url(clientDataJSON),
      authenticatorData: base64url(authenticatorData),
      signature: base64url(signature),
    });
  };


  const connectRecoveryWallet = async () => {
    try {
      setStatus("Connecting recovery wallet...");

      const kit = new StellarWalletsKit({
        network: WalletNetwork.TESTNET,
        selectedWalletId: undefined,
        modules: allowAllModules(),
      });

      await kit.openModal({
        onWalletSelected: async (option: any) => {
          kit.setWallet(option.id);
          const address = await kit.getAddress();
          setRecoveryAddress(address.address);
          setWalletKit(kit);
          setStatus(`Recovery wallet connected: ${address.address}`);
        },
      });
    } catch (error) {
      console.error("Recovery wallet connection error:", error);
      setStatus(`Failed to connect recovery wallet: ${error}`);
    }
  };

  const prepareRecoveryTransaction = async () => {
    if (!recoveryAddress || !loginWalletAddress || !walletKit) {
      setStatus("Missing recovery address, wallet address, or wallet kit");
      return;
    }

    try {
      setStatus("Preparing transaction...");

      // Create Soroban RPC client
      const server = new rpc.Server(RPC_URL);

      // Debug: Check what addresses we're working with
      console.log("Checking wallet addresses:");
      console.log("- loginWalletAddress (computed):", loginWalletAddress);
      console.log("- walletAddress (from deployment):", walletAddress);
      console.log("- loginIdentifier:", loginIdentifier);

      // Use the actually deployed address if available, otherwise use computed
      const targetWalletAddress = walletAddress || loginWalletAddress;
      console.log("- Using target address:", targetWalletAddress);

      // First, verify that the wallet contract actually exists
      setStatus("Verifying wallet contract exists...");
      try {
        const contractData = await server.getContractData(
          targetWalletAddress,
          xdr.ScVal.scvLedgerKeyContractInstance(),
          rpc.Durability.Persistent,
        );
        console.log("Wallet contract exists:", contractData);
      } catch (error) {
        throw new Error(
          `Wallet contract does not exist at address ${targetWalletAddress}. Please ensure the wallet was properly deployed. Error: ${error}`,
        );
      }

      // Build transaction that requires auth from both smart wallet AND recovery address
      // The smart wallet contract requires both the contract itself and the recovery address to authorize
      // We'll use the admin as the source account since we have the keys
      const deployerSecret = import.meta.env.VITE_DEPLOYER_SECRET;
      if (!deployerSecret) {
        throw new Error("VITE_DEPLOYER_SECRET not set in environment");
      }

      const adminKeypair = Keypair.fromSecret(deployerSecret);
      const adminAccount = await server.getAccount(adminKeypair.publicKey());
      const contract = new Contract(targetWalletAddress);

      // Create the contract operation that we'll reuse for both simulation and final transaction
      const contractOp = contract.call(
        "set_recovery",
        Address.fromString(recoveryAddress).toScVal(),
      );

      const transaction = new TransactionBuilder(adminAccount, {
        fee: "100000",
        networkPassphrase: NETWORK_PASSPHRASE,
      })
        .addOperation(contractOp)
        .setTimeout(30)
        .build();

      // First simulate the transaction to check for issues
      console.log("Simulating set_recovery transaction...");
      const simulatedTx = await server.simulateTransaction(transaction);

      if ("error" in simulatedTx) {
        throw new Error(`Simulation failed: ${simulatedTx.error}`);
      }

      console.log("Simulation successful:", simulatedTx);
      console.log("State changes:", simulatedTx.stateChanges);

      // Store simulation data and show modal
      setTxSimulation({
        functionName: "set_recovery",
        contract: targetWalletAddress,
        args: [{
          name: "recovery",
          type: "Address",
          value: recoveryAddress
        }],
        stateChanges: simulatedTx.stateChanges || [],
        authEntries: simulatedTx.result?.auth || [],
        simulation: simulatedTx
      });
      setShowTxModal(true);
      setStatus("Review transaction details...");

    } catch (error) {
      console.error("Transaction preparation error:", error);
      setStatus(`Failed to prepare transaction: ${error}`);
    }
  };

  const executeRecoveryTransaction = async () => {
    if (!txSimulation) return;
    
    try {
      setIsSettingRecovery(true);
      setShowTxModal(false);
      setStatus("Please authenticate with your passkey...");

      const server = new rpc.Server(RPC_URL);
      const targetWalletAddress = walletAddress || loginWalletAddress;

      // Get the auth entries from simulation
      const authEntries = txSimulation.authEntries;
      console.log("Auth entries from simulation:", authEntries);
      console.log("Number of auth entries:", authEntries.length);
      console.log("Looking for target wallet address:", targetWalletAddress);

      if (authEntries.length === 0) {
        throw new Error("No auth entries returned from simulation");
      }

      const smartWalletAuthEntry = authEntries.find(
        (entry: xdr.SorobanAuthorizationEntry) => {
          if (
            entry.credentials().switch() ===
              xdr.SorobanCredentialsType.sorobanCredentialsAddress()
          ) {
            if (
              entry.credentials().address().address().switch() ==
                xdr.ScAddressType.scAddressTypeContract()
            ) {
              return true;
            }
          }
          return false;
        },
      );

      if (!smartWalletAuthEntry) {
        throw new Error(
          `No auth entry found for smart wallet ${targetWalletAddress}`,
        );
      }

      console.log("Smart wallet auth entry found:", smartWalletAuthEntry);

      setStatus(
        "Please authenticate with your passkey to authorize the recovery setup...",
      );

      const signatureExpirationLedger = (await server.getLatestLedger()).sequence + 10;
      const signWebAuthnAuthEntry = async (
        authEntry: xdr.SorobanAuthorizationEntry,
      ): Promise<xdr.SorobanAuthorizationEntry> => {
        const addressCredentials = authEntry.credentials().address();
        const preimage = xdr.HashIdPreimage.envelopeTypeSorobanAuthorization(
          new xdr.HashIdPreimageSorobanAuthorization({
            networkId: hash(Buffer.from(NETWORK_PASSPHRASE)),
            nonce: addressCredentials.nonce(),
            signatureExpirationLedger: signatureExpirationLedger,
            invocation: authEntry.rootInvocation()
          })
        );
        
        const payload = hash(preimage.toXDR());
        const challenge = base64url(payload);

        const authentication = await startAuthentication({
          optionsJSON: {
            challenge,
            rpId: window.location.hostname,
            userVerification: "required",
          },
        });


        const clientDataJSON = authentication.response.clientDataJSON;
        const authenticatorData = authentication.response.authenticatorData;
        const signatureDER = base64url.toBuffer(
          authentication.response.signature,
        );

        // Convert DER signature to compact format with low-S normalization
        const compactSignature = (signatureDER: Buffer): Buffer => {
          const CURVE_ORDER = BigInt('0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551');
          const HALF_CURVE_ORDER = CURVE_ORDER / 2n;
          
          let offset = 2;
          
          if (signatureDER[offset] !== 0x02) throw new Error('Invalid signature format');
          offset++;
          const rLength = signatureDER[offset];
          offset++;
          const r = BigInt('0x' + signatureDER.slice(offset, offset + rLength).toString('hex'));
          offset += rLength;
          
          if (signatureDER[offset] !== 0x02) throw new Error('Invalid signature format');
          offset++;
          const sLength = signatureDER[offset];
          offset++;
          let s = BigInt('0x' + signatureDER.slice(offset, offset + sLength).toString('hex'));
          
          if (s > HALF_CURVE_ORDER) {
            s = CURVE_ORDER - s;
          }
          
          const rBuf = Buffer.alloc(32);
          const sBuf = Buffer.alloc(32);
          
          const rHex = r.toString(16).padStart(64, '0');
          const sHex = s.toString(16).padStart(64, '0');
          
          rBuf.write(rHex, 'hex');
          sBuf.write(sHex, 'hex');
          
          return Buffer.concat([rBuf, sBuf]);
        };
        
        const signature = compactSignature(Buffer.from(signatureDER));

        // Create WebAuthn credential structure for the smart contract
        // Convert the signature to a proper BytesN<64> type
        const signatureBuffer = Buffer.from(signature);
        if (signatureBuffer.length !== 64) {
          throw new Error(`Invalid signature length: ${signatureBuffer.length}, expected 64`);
        }
        
        const webAuthnCredential = xdr.ScVal.scvMap([
          new xdr.ScMapEntry({
            key: xdr.ScVal.scvSymbol('authenticator_data'),
            val: xdr.ScVal.scvBytes(Buffer.from(base64url.toBuffer(authenticatorData)))
          }),
          new xdr.ScMapEntry({
            key: xdr.ScVal.scvSymbol('client_data_json'),
            val: xdr.ScVal.scvBytes(Buffer.from(base64url.toBuffer(clientDataJSON)))
          }),
          new xdr.ScMapEntry({
            key: xdr.ScVal.scvSymbol('signature'),
            val: xdr.ScVal.scvBytes(signatureBuffer)
          })
        ]);
        
        
        authEntry.credentials().address().signature(webAuthnCredential);
        authEntry.credentials().address().signatureExpirationLedger(signatureExpirationLedger);

        return authEntry;
      };

      
      const signedSmartWalletAuthEntry = await signWebAuthnAuthEntry(
        smartWalletAuthEntry,
      );
      

      const deployerKeypair = Keypair.fromSecret(
        import.meta.env.VITE_DEPLOYER_SECRET,
      );
      const sourceAccount = await server.getAccount(
        deployerKeypair.publicKey(),
      );

      const contract = new Contract(targetWalletAddress);
      const contractOp = contract.call(
        "set_recovery",
        Address.fromString(recoveryAddress).toScVal(),
      );

      contractOp.body().invokeHostFunctionOp().auth([signedSmartWalletAuthEntry]);

      const finalTransaction = new TransactionBuilder(sourceAccount, {
        fee: "1000000",
        networkPassphrase: NETWORK_PASSPHRASE,
      })
        .addOperation(contractOp)
        .setTimeout(30)
        .build();

      const preparedTransaction = await server.prepareTransaction(finalTransaction);
      preparedTransaction.sign(deployerKeypair);

      const result = await server.sendTransaction(preparedTransaction);

      if (result.status === "PENDING") {
        console.log("Transaction submitted successfully:", result.hash);
        
        setStatus("Waiting for transaction confirmation...");

        // Wait for the transaction to be processed
        await new Promise((resolve) => setTimeout(resolve, 5000));

        // Verify the recovery address was set by calling the recovery() method
        console.log("Verifying recovery address was set...");

        try {
          const contract = new Contract(targetWalletAddress);
          const rpcServer = new rpc.Server(RPC_URL);
          const sourceAccount = await rpcServer.getAccount(
            Keypair.fromSecret(import.meta.env.VITE_DEPLOYER_SECRET)
              .publicKey(),
          );
          const recoveryCall = contract.call("recovery");
          const recoveryResult = await rpcServer.simulateTransaction(
            new TransactionBuilder(sourceAccount, {
              fee: "100",
              networkPassphrase: NETWORK_PASSPHRASE,
            })
              .addOperation(recoveryCall)
              .setTimeout(300)
              .build(),
          );

          if ("result" in recoveryResult && recoveryResult.result) {
            const recoveryAddressFromContract = scValToNative(
              recoveryResult.result.retval,
            );
            console.log(
              "Recovery address from contract:",
              recoveryAddressFromContract,
            );

            if (recoveryAddressFromContract === recoveryAddress) {
              console.log("✅ Recovery address verification successful!");
              setStatus(
                `Recovery address set successfully! Verified: ${recoveryAddressFromContract}`,
              );
              // Update the displayed recovery address
              setCurrentRecoveryAddress(recoveryAddressFromContract);
            } else {
              console.log("❌ Recovery address mismatch!");
              setStatus(
                `Recovery set but address mismatch. Expected: ${recoveryAddress}, Got: ${recoveryAddressFromContract}`,
              );
              // Still update the display with what was actually set
              setCurrentRecoveryAddress(recoveryAddressFromContract);
            }
          } else {
            console.log("❌ No recovery address found");
            setStatus("Recovery address appears to not be set");
          }
        } catch (verificationError) {
          console.log("Recovery verification error:", verificationError);
          setStatus("Recovery set successfully, but verification failed");
        }
      } else {
        console.error(
          "Transaction failed with full result:",
          JSON.stringify(result, null, 2),
        );
        throw new Error(
          `Transaction failed: ${result.status} - ${
            JSON.stringify(result.errorResult || result)
          }`,
        );
      }
      
      // Refresh the recovery address display after transaction completion
      await fetchRecoveryAddress(targetWalletAddress);
    } catch (error) {
      console.error("Set recovery error:", error);
      setStatus(`Failed to set recovery: ${error}`);
    } finally {
      setIsSettingRecovery(false);
    }
  };

  const rotateToNewPasskey = async () => {
    if (!newPasskeyDisplayName.trim()) {
      setStatus("Please enter a display name for the new passkey");
      return;
    }

    if (!recoveryAddress || !walletKit) {
      setStatus("Please connect recovery wallet first");
      return;
    }

    try {
      setIsRotatingSigner(true);
      setStatus("Creating new passkey...");

      // Create new passkey
      const newRegistration = await startRegistration({
        optionsJSON: {
          challenge: base64url("new-passkey-challenge"),
          rp: {
            name: "Smart Wallet Demo",
            id: window.location.hostname,
          },
          user: {
            id: base64url(userIdentifier || loginIdentifier), // Keep original identifier for address derivation
            name: (userIdentifier || loginIdentifier).toLowerCase().trim(), // Use original identifier for name
            displayName: newPasskeyDisplayName.trim(), // Use new display name for this specific passkey
          },
          pubKeyCredParams: [{ alg: -7, type: "public-key" }],
          authenticatorSelection: {
            authenticatorAttachment: "platform",
            residentKey: "preferred",
            userVerification: "required",
          },
          attestation: "none",
        },
      });

      const newPublicKeyBytes = extractPublicKey(newRegistration.response);

      if (!newPublicKeyBytes) {
        throw new Error("Failed to extract public key from new passkey");
      }

      const newPublicKeyHex = Array.from(newPublicKeyBytes)
        .map((b) => b.toString(16).padStart(2, "0"))
        .join("");

      setStatus("New passkey created! Now rotating signer...");

      // Create Soroban RPC client
      const server = new rpc.Server(RPC_URL);

      // Now that the contract bug is fixed, rotate_signer uses RecoveryAddress correctly
      // So we need to sign with the recovery wallet
      if (!recoveryAddress || !walletKit) {
        throw new Error("Recovery wallet not connected");
      }

      // Use the actually deployed address if available, otherwise use computed
      const targetWalletAddress = walletAddress || loginWalletAddress;
      console.log(
        "Using target wallet address for rotation:",
        targetWalletAddress,
      );

      const contract = new Contract(targetWalletAddress);

      // Use the recovery address as the source account
      const recoveryAccount = await server.getAccount(recoveryAddress);

      const transaction = new TransactionBuilder(recoveryAccount, {
        fee: "100000",
        networkPassphrase: NETWORK_PASSPHRASE,
      })
        .addOperation(
          contract.call(
            "rotate_signer",
            nativeToScVal(
              Uint8Array.from(newPublicKeyHex.match(/.{1,2}/g)!.map((byte) =>
                parseInt(byte, 16)
              )),
              { type: "bytes" },
            ),
          ),
        )
        .setTimeout(30)
        .build();

      // Simulate the transaction first
      setStatus("Simulating signer rotation transaction...");
      const simulatedTx = await server.simulateTransaction(transaction);

      if ("error" in simulatedTx) {
        throw new Error(`Simulation failed: ${simulatedTx.error}`);
      }

      // Prepare the transaction with proper fees and resource limits
      const preparedTx = await server.prepareTransaction(transaction);

      setStatus(
        "Please sign the rotation transaction with your recovery wallet...",
      );

      // Sign with the recovery wallet
      const signedTransaction = await walletKit.signTransaction(
        preparedTx.toXDR(),
        {
          networkPassphrase: NETWORK_PASSPHRASE,
        },
      );

      const finalTx = TransactionBuilder.fromXDR(
        signedTransaction.signedTxXdr,
        NETWORK_PASSPHRASE,
      );

      // Submit the transaction
      const result = await server.sendTransaction(finalTx);

      if (result.status === "PENDING") {
        setStatus("Waiting for signer rotation confirmation...");

        // Wait for confirmation
        let getResponse = await server.getTransaction(result.hash);
        while (getResponse.status === "NOT_FOUND") {
          await new Promise((resolve) => setTimeout(resolve, 1000));
          getResponse = await server.getTransaction(result.hash);
        }

        if (getResponse.status === "SUCCESS") {
          setStatus(
            "✓ Signer rotated successfully! The wallet now uses the new passkey.",
          );

          // Update the current credentials
          setPublicKey(newPublicKeyHex);
          setCredentialId(newRegistration.id);
          
          // Trigger flash animation for credential ID
          setShouldFlashCredentialId(true);
          setTimeout(() => setShouldFlashCredentialId(false), 2000);
        } else {
          throw new Error("Signer rotation transaction failed");
        }
      } else {
        setStatus(
          "✓ Signer rotated successfully! The wallet now uses the new passkey.",
        );

        // Update the current credentials
        setPublicKey(newPublicKeyHex);
        setCredentialId(newRegistration.id);
        
        // Trigger flash animation for credential ID
        setShouldFlashCredentialId(true);
        setTimeout(() => setShouldFlashCredentialId(false), 2000);
      }
    } catch (error) {
      console.error("Rotate signer error:", error);
      setStatus(`Failed to rotate signer: ${error}`);
    } finally {
      setIsRotatingSigner(false);
    }
  };

  return (
    <div className="app-container">
      <div className="wallet-header">
        <h1>Smart Wallet</h1>
        <p>WebAuthn Recovery Demo</p>
      </div>

      <div className="card">
        <div className="step-header">
          <span className={`step-badge ${walletAddress ? 'completed' : ''}`}>
            {walletAddress ? "✓" : "1"}
          </span>
          <h2>Create Smart Wallet</h2>
        </div>

        <p style={{ marginBottom: '1.5rem', color: '#64748b' }}>
          Create a smart contract wallet secured by your device's biometric authentication. 
        </p>
        <p style={{ fontSize: '0.875rem', color: '#94a3b8', marginBottom: '1.5rem' }}>
          <strong>How it works:</strong> Your wallet's contract address is deterministically derived from your 
          email/username. This means the same identifier always generates the same wallet address, 
          allowing you to access your wallet from any device.
        </p>

        {!walletAddress && (
          <div className="input-group">
            <label htmlFor="userIdentifier">Email or Username:</label>
            <input
              id="userIdentifier"
              type="text"
              value={userIdentifier}
              onChange={(e) => setUserIdentifier(e.target.value)}
              placeholder="Enter email or username"
              disabled={isDeploying}
            />
          </div>
        )}

        <button
          className="btn-primary"
          onClick={handleRegisterAndDeploy}
          disabled={!!walletAddress || isDeploying || !userIdentifier.trim()}
        >
          {isDeploying
            ? "Creating..."
            : walletAddress
            ? "Wallet Created ✓"
            : "Create Wallet with Passkey"}
        </button>

        {credentialId && userIdentifier && (
          <div className="info-panel">
            <div className="info-item">
              <strong>Identifier:</strong> {userIdentifier}
            </div>
            <div className={`info-item ${shouldFlashCredentialId ? 'flash-update' : ''}`}>
              <strong>Credential ID:</strong> {credentialId.slice(0, 20)}...
            </div>
            <div className="info-item">
              <strong>Public Key:</strong> {publicKey.slice(0, 20)}...
            </div>
          </div>
        )}

        {walletAddress && (
          <div className="info-panel success">
            <div className="info-item">
              <strong>Wallet Address:</strong>{' '}
              <a 
                href={`https://stellar.expert/explorer/testnet/contract/${walletAddress}`}
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: '#0066cc', textDecoration: 'none' }}
              >
                {walletAddress}
              </a>
            </div>
          </div>
        )}
        
        {!walletAddress && isLoggedIn && loginWalletAddress && (
          <div className="info-panel">
            <div className="info-item">
              <strong>Note:</strong> You're logged in to wallet:{' '}
              <a 
                href={`https://stellar.expert/explorer/testnet/contract/${loginWalletAddress}`}
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: '#0066cc', textDecoration: 'none' }}
              >
                {loginWalletAddress.slice(0, 20)}...
              </a>
            </div>
            <div className="info-item">
              This wallet was created in a previous session.
            </div>
          </div>
        )}
      </div>

      <div className="card">
        <div className="step-header">
          <span className={`step-badge ${isLoggedIn ? 'completed' : ''}`}>
            {isLoggedIn ? "✓" : "2"}
          </span>
          <h2>Login with Existing Passkey</h2>
        </div>

        {!isLoggedIn && !showLoginFallback && (
          <>
            <p style={{ marginBottom: '1.5rem', color: '#64748b' }}>
              Use your device's biometric authentication to access your existing wallet. 
              Your passkey proves you own this wallet without needing passwords.
            </p>
            <p style={{ fontSize: '0.875rem', color: '#94a3b8', fontStyle: 'italic' }}>
              Note: Some browsers/devices don't store your identifier with the passkey, 
              so you may be asked to enter your email/username to derive your wallet address.
            </p>
            <button className="btn-primary" onClick={handleLoginWithPasskey}>
              Login with Passkey
            </button>
          </>
        )}

        {!isLoggedIn && showLoginFallback && (
          <>
            <p style={{ color: '#64748b', marginBottom: '1rem' }}>
              ✅ Your passkey was successfully authenticated!
            </p>
            <p style={{ color: '#64748b' }}>
              However, your browser/device didn't store your identifier with the passkey 
              (this varies by implementation). Since your wallet address is deterministically 
              derived from your identifier, please enter the exact same email/username 
              you used when creating the wallet:
            </p>
            <div className="input-group">
              <label htmlFor="loginIdentifier">Your Email or Username:</label>
              <input
                id="loginIdentifier"
                type="text"
                value={loginIdentifier}
                onChange={(e) => setLoginIdentifier(e.target.value)}
                placeholder="Enter the same identifier you used to create the wallet"
              />
            </div>
            <div className="button-group">
              <button
                className="btn-primary"
                onClick={handleLoginFallback}
                disabled={!loginIdentifier.trim()}
              >
                Complete Login
              </button>
              <button
                className="btn-secondary"
                onClick={() => {
                  setShowLoginFallback(false);
                  setLoginIdentifier("");
                  setCredentialId("");
                  setStatus("");
                }}
              >
                Cancel
              </button>
            </div>
          </>
        )}

        {isLoggedIn && (
          <div className="info-panel authenticated">
            <div className="info-item">
              <strong>Status:</strong> <span className="status-badge">Authenticated</span>
            </div>
            <div className="info-item">
              <strong>Identifier:</strong> {loginIdentifier}
            </div>
            <div className={`info-item ${shouldFlashCredentialId ? 'flash-update' : ''}`}>
              <strong>Credential ID:</strong> {credentialId.slice(0, 20)}...
            </div>
            {loginWalletAddress && (
              <div className="info-item">
                <strong>Wallet Address:</strong>{' '}
                <a 
                  href={`https://stellar.expert/explorer/testnet/contract/${loginWalletAddress}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  style={{ color: '#0066cc', textDecoration: 'none' }}
                >
                  {loginWalletAddress}
                </a>
              </div>
            )}
            {loginPublicKey &&
              loginPublicKey !== "(Would extract from credential)" && (
              <div className="info-item">
                <strong>Public Key:</strong> {loginPublicKey.slice(0, 20)}...
              </div>
            )}
          </div>
        )}
      </div>

      {isLoggedIn && loginWalletAddress && (
        <div className="card">
          <div className="step-header">
            <span className={`step-badge ${currentRecoveryAddress ? 'completed' : ''}`}>
              {currentRecoveryAddress ? "✓" : "3"}
            </span>
            <h2>Recovery Setup</h2>
          </div>

          <p style={{ marginBottom: '1.5rem', color: '#64748b' }}>
            Add a backup wallet that can help you regain access if you lose your device. 
            This could be a hardware wallet, another phone, or a trusted friend's wallet.
          </p>

          <div className="info-panel">
            <div className="info-item">
              <strong>Wallet Address:</strong>{' '}
              <a 
                href={`https://stellar.expert/explorer/testnet/contract/${loginWalletAddress}`}
                target="_blank"
                rel="noopener noreferrer"
                style={{ color: '#0066cc', textDecoration: 'none' }}
              >
                {loginWalletAddress}
              </a>
            </div>
            {currentRecoveryAddress
              ? (
                <div className="info-item" style={{ color: "#059669", fontWeight: "500" }}>
                  <strong>Current Recovery Address:</strong>{' '}
                  <a 
                    href={`https://stellar.expert/explorer/testnet/account/${currentRecoveryAddress}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{ color: '#059669', textDecoration: 'none' }}
                  >
                    {currentRecoveryAddress}
                  </a> ✅
                </div>
              )
              : (
                <div className="info-item">
                  <strong>Recovery Address:</strong> Not set
                </div>
              )}
          </div>

          {!recoveryAddress
            ? (
              <div>
                <p>Connect a Stellar wallet to act as the recovery signer:</p>
                <button className="btn-primary" onClick={connectRecoveryWallet}>
                  Connect Recovery Wallet
                </button>
              </div>
            )
            : (
              <div>
                <div className="info-panel">
                  <div className="info-item">
                    <strong>Recovery Wallet:</strong>{' '}
                    <a 
                      href={`https://stellar.expert/explorer/testnet/account/${recoveryAddress}`}
                      target="_blank"
                      rel="noopener noreferrer"
                      style={{ color: '#0066cc', textDecoration: 'none' }}
                    >
                      {recoveryAddress}
                    </a>
                  </div>
                </div>

                <button
                  className="btn-primary"
                  onClick={prepareRecoveryTransaction}
                  disabled={isSettingRecovery || !!currentRecoveryAddress}
                >
                  {isSettingRecovery ? "Setting..." : "Set as Recovery Signer"}
                </button>
                
                {currentRecoveryAddress && (
                  <p className="helper-text">
                    Recovery address is already set
                  </p>
                )}
              </div>
            )}
        </div>
      )}

      {isLoggedIn && loginWalletAddress && recoveryAddress && (
        <div className="card">
          <div className="step-header">
            <span className="step-badge">4</span>
            <h2>Rotate to New Passkey</h2>
          </div>

          <p style={{ marginBottom: '1.5rem', color: '#64748b' }}>
            Lost your device? Got a new phone? Use your recovery wallet to switch to a new passkey. 
            This replaces your old device authentication with a new one.
          </p>
          
          <div style={{ 
            background: '#fef3c7', 
            border: '1px solid #f59e0b', 
            borderRadius: '8px', 
            padding: '1rem', 
            marginBottom: '1.5rem' 
          }}>
            <strong style={{ color: '#92400e' }}>⚠️ Important:</strong>
            <p style={{ margin: '0.5rem 0 0 0', color: '#92400e' }}>
              When logging in on your new device, you MUST use the exact same email/username 
              as when you first created the wallet. The wallet address is deterministically derived 
              from this identifier - using a different one will generate a different address.
            </p>
          </div>

          <div className="input-group">
            <label htmlFor="newPasskeyDisplayName">New Passkey Display Name:</label>
            <input
              id="newPasskeyDisplayName"
              type="text"
              placeholder="Enter name for new passkey"
              value={newPasskeyDisplayName}
              onChange={(e) => setNewPasskeyDisplayName(e.target.value)}
              disabled={isRotatingSigner}
            />
          </div>

          <button
            className="btn-primary"
            onClick={rotateToNewPasskey}
            disabled={isRotatingSigner || !newPasskeyDisplayName.trim()}
          >
            {isRotatingSigner ? "Rotating..." : "Create New Passkey & Rotate Signer"}
          </button>

          <p className="helper-text">
            This will create a new passkey and set it as the wallet's signer,
            replacing the current one. The rotation will be authorized by your
            recovery wallet.
          </p>
        </div>
      )}

      {status && (
        <div className="status-bar">
          <p>{status}</p>
        </div>
      )}

      {/* Transaction Review Modal */}
      {showTxModal && txSimulation && (
        <div className="modal-overlay" onClick={() => setShowTxModal(false)}>
          <div className="modal-content" onClick={(e) => e.stopPropagation()}>
            <div className="modal-header">
              <h3>🔐 Sign Transaction</h3>
            </div>
            <div className="modal-body">
              <div className="tx-summary">
                <h4>Contract Call</h4>
                <div className="tx-detail-item">
                  <span className="tx-detail-label">Contract:</span>
                  <span className="tx-detail-value tx-detail-address">
                    {txSimulation.contract}
                  </span>
                </div>
                <div className="tx-detail-item">
                  <span className="tx-detail-label">Function:</span>
                  <span className="tx-detail-value" style={{ fontFamily: 'monospace', fontWeight: 600 }}>
                    {txSimulation.functionName}
                  </span>
                </div>
              </div>

              <div className="tx-summary">
                <h4>Arguments</h4>
                {txSimulation.args.map((arg: any, index: number) => (
                  <div key={index} className="tx-detail-item">
                    <span className="tx-detail-label">{arg.name} ({arg.type}):</span>
                    <span className="tx-detail-value tx-detail-address">
                      {arg.value}
                    </span>
                  </div>
                ))}
              </div>



              <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
                <p><strong>What this does:</strong></p>
                <p>Sets the specified address as a recovery signer for your smart wallet. 
                This address will be able to help you regain access if you lose your device.</p>
              </div>
            </div>
            <div className="modal-footer">
              <button 
                className="btn-primary" 
                onClick={executeRecoveryTransaction}
                style={{ width: '100%' }}
              >
                Sign Transaction
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
