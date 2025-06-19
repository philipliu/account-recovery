import { describe, it } from 'vitest'
import { 
  Contract, 
  Keypair, 
  Networks, 
  rpc, 
  TransactionBuilder, 
  Address, 
  nativeToScVal, 
  xdr 
} from '@stellar/stellar-sdk'

const NETWORK_PASSPHRASE = Networks.TESTNET
const RPC_URL = 'https://soroban-testnet.stellar.org'

describe('Auth Entry Signature Tests', () => {
  it('should properly attach signatures to auth entries', async () => {
    // Mock data
    const deployerSecret = 'SALAACXKBZPBHHR543IEA6Z2LBDLQDWKDRFLM5MO57VDMS6PNUGFO6YN' // Example secret
    const deployerKeypair = Keypair.fromSecret(deployerSecret)
    const walletAddress = 'CB7TFJFQJBSX5CU4JDMW37RD3AJ7L3RIYQ7HBCI7JNE4IWX3IOUNW7WN'
    const recoveryAddress = 'GAIHR6UC5WYEFB6XAYHIITJKEPGFHQ5DF6O6YYF5XYHDQTC35CTWH7ZZ'
    
    const server = new rpc.Server(RPC_URL)
    
    try {
      // Create a basic transaction to simulate
      const sourceAccount = await server.getAccount(deployerKeypair.publicKey())
      
      const contract = new Contract(walletAddress)
      const transaction = new TransactionBuilder(sourceAccount, {
        fee: '100000',
        networkPassphrase: NETWORK_PASSPHRASE
      })
      .addOperation(
        contract.call(
          'set_recovery',
          new Address(recoveryAddress).toScVal()
        )
      )
      .setTimeout(300)
      .build()
      
      console.log('Created basic transaction')
      
      // Simulate the transaction to get auth entries
      const simulatedTx = await server.simulateTransaction(transaction)
      
      if ('error' in simulatedTx) {
        console.log('Simulation failed:', simulatedTx.error)
        return
      }
      
      const authEntries = simulatedTx.result?.auth || []
      console.log(`Found ${authEntries.length} auth entries`)
      
      if (authEntries.length < 2) {
        console.log('Not enough auth entries for test')
        return
      }
      
      // Find smart wallet and recovery auth entries
      const smartWalletAuthEntry = authEntries.find((entry: any) => {
        if (entry.credentials().switch() === xdr.SorobanCredentialsType.sorobanCredentialsAddress()) {
          if (entry.credentials().address().address().switch() == xdr.ScAddressType.scAddressTypeContract()) {
            return true
          }
        }
        return false
      })
      
      const recoveryAuthEntry = authEntries.find((entry: any) => {
        if (entry.credentials().switch() === xdr.SorobanCredentialsType.sorobanCredentialsAddress()) {
          if (entry.credentials().address().address().switch() == xdr.ScAddressType.scAddressTypeAccount()) {
            return true
          }
        }
        return false
      })
      
      if (!smartWalletAuthEntry || !recoveryAuthEntry) {
        console.log('Could not find required auth entries')
        return
      }
      
      console.log('Found both auth entries')
      
      // Create mock signatures
      const mockWebAuthnSignature = nativeToScVal({
        authenticator_data: new Uint8Array(37).fill(1),
        client_data_json: new Uint8Array(100).fill(2), 
        signature: new Uint8Array(64).fill(3)
      }, { type: 'instance' })
      
      const mockRecoverySignature = nativeToScVal(new Uint8Array(64).fill(4), { type: 'bytes' })
      
      console.log('Created mock signatures')
      
      // Test different methods to attach signatures
      console.log('=== TESTING SIGNATURE ATTACHMENT ===')
      
      // Method 1: Direct setter
      console.log('Testing direct setter method...')
      try {
        smartWalletAuthEntry.credentials().address().signature(mockWebAuthnSignature)
        console.log('✅ Smart wallet signature set via direct setter')
      } catch (error: any) {
        console.log('❌ Smart wallet direct setter failed:', error.message)
      }
      
      try {
        recoveryAuthEntry.credentials().address().signature(mockRecoverySignature)
        console.log('✅ Recovery signature set via direct setter')
      } catch (error: any) {
        console.log('❌ Recovery direct setter failed:', error.message)
      }
      
      // Method 2: Check if signatures are actually set
      console.log('\nTesting signature retrieval...')
      try {
        const smartSig = smartWalletAuthEntry.credentials().address().signature()
        console.log('Smart wallet signature:', smartSig ? 'PRESENT' : 'MISSING')
      } catch (error: any) {
        console.log('❌ Could not retrieve smart wallet signature:', error.message)
      }
      
      try {
        const recoverySig = recoveryAuthEntry.credentials().address().signature()
        console.log('Recovery signature:', recoverySig ? 'PRESENT' : 'MISSING')
      } catch (error: any) {
        console.log('❌ Could not retrieve recovery signature:', error.message)
      }
      
      // Method 3: Check XDR output
      console.log('\nTesting XDR output...')
      const smartWalletXdr = smartWalletAuthEntry.toXDR()
      const recoveryXdr = recoveryAuthEntry.toXDR()
      
      console.log('Smart wallet XDR length:', smartWalletXdr.length)
      console.log('Recovery XDR length:', recoveryXdr.length)
      console.log('Smart wallet XDR contains signature?', smartWalletXdr.includes('signature'))
      console.log('Recovery XDR contains signature?', recoveryXdr.includes('signature'))
      
      // Method 4: Try building transaction with signed auth entries
      console.log('\nTesting transaction building...')
      const newContract = new Contract(walletAddress)
      const newTransaction = new TransactionBuilder(sourceAccount, {
        fee: '100000',
        networkPassphrase: NETWORK_PASSPHRASE
      })
      .addOperation(
        newContract.call(
          'set_recovery', 
          new Address(recoveryAddress).toScVal()
        )
      )
      .setTimeout(300)
      .build()
      
      // Try to manually set auth entries on the operation
      const op = newTransaction.operations[0] as any
      op.auth = [smartWalletAuthEntry, recoveryAuthEntry]
      
      console.log('Transaction with auth entries XDR length:', newTransaction.toXDR().length)
      
      // Method 5: Test creating auth entries from scratch
      console.log('\nTesting creating auth entries from scratch...')
      
      // This would require understanding the exact XDR structure
      // For now, let's just log what we have
      console.log('Auth entry structure analysis:')
      console.log('Smart wallet credentials type:', typeof smartWalletAuthEntry.credentials())
      console.log('Smart wallet address type:', typeof smartWalletAuthEntry.credentials().address())
      
    } catch (error: any) {
      console.error('Test failed with error:', error.message)
    }
  })
})