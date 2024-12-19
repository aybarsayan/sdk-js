/**
 * Copyright (c) 2018-2024, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { u8aEq, u8aToHex, u8aToU8a } from '@polkadot/util'
import { base58Decode, base58Encode } from '@polkadot/util-crypto'
import type { ApiPromise } from '@polkadot/api'
import type { U8aLike } from '@polkadot/util/types'
import { authorizeTx } from '@kiltprotocol/did'
import { ConfigService } from '@kiltprotocol/config'
import type {
  Caip2ChainId,
  KiltAddress,
  SignerInterface,
  MultibaseKeyPair,
} from '@kiltprotocol/types'
import { Caip2, SDKErrors, Signers } from '@kiltprotocol/utils'
import { Blockchain } from '@kiltprotocol/chain-helpers'
import * as CType from '../ctype/index.js'
import * as Attestation from '../attestation/index.js'
import {
  assertMatchingConnection,
  getDelegationNodeIdForCredential,
} from './common.js'
import type { IssuerOptions } from '../interfaces.js'
import type {
  KiltCredentialV1,
  KiltRevocationStatusV1,
  VerifiableCredential,
} from './types.js'

export type Interface = KiltRevocationStatusV1

export const STATUS_TYPE = 'KiltRevocationStatusV1'

interface RevokeResult {
  success: boolean
  error?: string[]
  info: {
    blockNumber?: string
    blockHash?: string
    transactionHash?: string
  }
}

interface BlockchainResponse {
  blockNumber: string
  status: {
    finalized: string
  }
  txHash: string
}

/**
 * Revokes a Kilt credential on the blockchain, making it invalid.
 *
 * @param params Named parameters for the revocation process.
 * @param params.issuer Interfaces for interacting with the issuer identity.
 * @param params.issuer.didDocument The DID Document of the issuer revoking the credential.
 * @param params.issuer.signers Array of signer interfaces for credential authorization.
 * @param params.issuer.submitter The submitter can be one of:
 * - A MultibaseKeyPair for signing transactions
 * - A Ed25519 type keypair for blockchain interactions
 * The submitter will be used to cover transaction fees and blockchain operations.
 * @param params.credential The Verifiable Credential to be revoked. Must contain a valid credential ID.
 * @param issuer
 * @param credential
 * @returns An object containing:
 * - success: Boolean indicating if revocation was successful
 * - error?: Array of error messages if revocation failed
 * - info: Object containing blockchain transaction details:
 *   - blockNumber?: The block number where revocation was included
 *   - blockHash?: The hash of the finalized block
 *   - transactionHash?: The hash of the revocation transaction.
 * @throws Will return error response if:
 * - Credential ID is invalid or cannot be decoded
 * - DID authorization fails
 * - Transaction signing or submission fails.
 */
export async function revoke(
  issuer: IssuerOptions,
  credential: VerifiableCredential
): Promise<RevokeResult> {
  try {
    if (!credential.id) {
      throw new Error('Credential ID is required for revocation')
    }

    const rootHash = credential.id.split(':').pop()
    if (!rootHash) {
      throw new Error('Invalid credential ID format')
    }

    const decodedroothash = base58Decode(rootHash)
    const { didDocument, signers, submitter } = issuer
    const api = ConfigService.get('api')

    const revokeTx = api.tx.attestation.revoke(decodedroothash, null) as any
    const [Txsubmitter] = (await Signers.getSignersForKeypair({
      keypair: submitter as MultibaseKeyPair,
      type: 'Ed25519',
    })) as Array<SignerInterface<'Ed25519', KiltAddress>>
    const authorizedTx = await authorizeTx(
      didDocument,
      revokeTx,
      signers as SignerInterface[],
      Txsubmitter.id
    )

    const response = (await Blockchain.signAndSubmitTx(
      authorizedTx,
      Txsubmitter
    )) as unknown as BlockchainResponse

    const responseObj = JSON.parse(JSON.stringify(response))

    return {
      success: true,
      info: {
        blockNumber: responseObj.blockNumber,
        blockHash: responseObj.status.finalized,
        transactionHash: responseObj.txHash,
      },
    }
  } catch (error: unknown) {
    const errorMessage =
      error instanceof Error ? error.message : 'Unknown error occurred'
    return {
      success: false,
      error: [errorMessage],
      info: {},
    }
  }
}

/**
 * Check attestation and revocation status of a credential at the latest block available.
 *
 * @param credential The KiltCredentialV1 to which the status method is linked to.
 * @param opts Additional parameters.
 * @param opts.api An optional polkadot-js/api instance connected to the blockchain network on which the credential is anchored.
 * If not given this function will try to retrieve a cached connection from the {@link ConfigService}.
 */
export async function check(
  credential: Omit<KiltCredentialV1, 'proof'>,
  opts: { api?: ApiPromise } = {}
): Promise<void> {
  const { credentialStatus } = credential
  if (credentialStatus?.type !== STATUS_TYPE)
    throw new TypeError(
      `The credential must have a credentialStatus of type ${STATUS_TYPE}`
    )
  const { api = ConfigService.get('api') } = opts
  const { assetNamespace, assetReference, assetInstance } =
    assertMatchingConnection(api, credential)
  if (assetNamespace !== 'kilt' || assetReference !== 'attestation') {
    throw new Error(
      `Cannot handle revocation status checks for asset type ${assetNamespace}:${assetReference}`
    )
  }
  if (!assetInstance) {
    throw new SDKErrors.CredentialMalformedError(
      "The attestation record's CAIP-19 identifier must contain an asset index ('token_id') decoding to the credential root hash"
    )
  }
  const rootHash = base58Decode(assetInstance)
  const encoded = await api.query.attestation.attestations(rootHash)
  if (encoded.isNone)
    throw new SDKErrors.CredentialUnverifiableError(
      `Attestation data not found at latest block ${encoded.createdAtHash}`
    )

  const decoded = Attestation.fromChain(encoded, u8aToHex(rootHash))
  const onChainCType = CType.hashToId(decoded.cTypeHash)
  const delegationId = getDelegationNodeIdForCredential(credential)
  if (
    decoded.owner !== credential.issuer ||
    !credential.type.includes(onChainCType) ||
    !u8aEq(
      delegationId ?? new Uint8Array(),
      decoded.delegationId ?? new Uint8Array()
    )
  ) {
    throw new SDKErrors.CredentialUnverifiableError(
      `Credential not matching on-chain data: issuer "${decoded.owner}", CType: "${onChainCType}", Delegation: "${decoded.delegationId}"`
    )
  }
  if (decoded.revoked !== false) {
    throw new SDKErrors.CredentialUnverifiableError('Attestation revoked')
  }
}

/**
 * Creates a {@link KiltRevocationStatusV1} object from a credential hash and blochain identifier, which allow locating the credential's attestation record.
 *
 * @param chainIdOrGenesisHash The genesis hash (or CAIP-2 identifier) of the substrate chain on which the attestation record lives.
 * @param rootHash The credential hash identifying the relevant attestation record on that chain.
 * @returns A new {@link KiltRevocationStatusV1} object.
 */
export function fromGenesisAndRootHash(
  chainIdOrGenesisHash: Caip2ChainId | U8aLike,
  rootHash: U8aLike
): KiltRevocationStatusV1 {
  const chainId =
    typeof chainIdOrGenesisHash === 'string' &&
    chainIdOrGenesisHash.startsWith('polkadot')
      ? chainIdOrGenesisHash
      : Caip2.chainIdFromGenesis(u8aToU8a(chainIdOrGenesisHash))

  return {
    id: `${chainId}/kilt:attestation/${base58Encode(rootHash)}`,
    type: STATUS_TYPE,
  }
}
