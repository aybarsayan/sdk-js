/**
 * Copyright (c) 2018-2024, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

import { SDKErrors, Signers } from '@kiltprotocol/utils'
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import * as KiltChain from '@kiltprotocol/chain-helpers'
// import * as Kilt from '@kiltprotocol/sdk-js'
// import * as KiltChain from '@kiltprotocol/chain-helpers'
import type {
  KiltAddress,
  SignerInterface,
  Did,
  ICType,
  IClaimContents,
  MultibaseKeyPair,
} from '@kiltprotocol/types'
import { authorizeTx } from '@kiltprotocol/did'
import { base58Decode } from '@polkadot/util-crypto'
import { ConfigService } from '@kiltprotocol/config'
import type { IssuerOptions, SubmitOverride } from './interfaces.js'
import type { CTypeLoader } from './ctype/index.js'
import type { UnsignedVc, VerifiableCredential } from './V1/types.js'
import { KiltAttestationProofV1, KiltCredentialV1 } from './V1/index.js'

export type { IssuerOptions }

/**
 * Creates a new credential document as a basis for issuing a credential.
 * This document can be shown to users as a preview or be extended with additional properties before moving on to the second step of credential issuance:
 * Adding a `proof` to the document using the {@link issue} function to make the credential verifiable.
 *
 * @param arguments Object holding all arguments for credential creation.
 * @param arguments.issuer The Decentralized Identifier (DID) of the identity acting as the authority issuing this credential.
 * @param arguments.credentialSubject An object containing key-value pairs that represent claims made about the subject of the credential.
 * @param arguments.credentialSubject.id The DID identifying the subject of the credential, about which claims are made (the remaining key-value pairs).
 * @param arguments.cType CTypes are special credential subtypes that are defined by a schema describing claims that may be made about the subject and are registered on the Kilt blockchain.
 * Each Kilt credential is based on exactly one of these subtypes. This argument is therefore mandatory and expects the schema definition of a CType.
 * @param arguments.cTypeDefinitions Some CTypes are themselves composed of definitions taken from other CTypes; in that case, these definitions need to be supplied here.
 * Alternatively, you can set a {@link CTypeLoader} function that takes care of fetching all required definitions.
 * @param arguments.type A type string identifying the (sub-)type of Verifiable Credential to be created.
 * This is added to the `type` field on the credential and determines the `credentialSchema` as well.
 * Defaults to the type {@link KiltCredentialV1.CREDENTIAL_TYPE KiltCredentialV1} which, for the time being, is also the only type supported.
 * @returns A (potentially only partial) credential that is yet to be finalized and made verifiable with a proof.
 */
export async function createCredential({
  issuer,
  credentialSubject,
  cType,
  cTypeDefinitions,
  type,
}: {
  issuer: Did
  credentialSubject: Record<string, unknown> & { id: Did }
  cType: ICType
  cTypeDefinitions?: ICType[] | CTypeLoader
  type?: string
}): Promise<UnsignedVc> {
  switch (type) {
    case undefined:
    case KiltCredentialV1.CREDENTIAL_TYPE: {
      const { id: subject, ...claims } = credentialSubject
      const credential = KiltCredentialV1.fromInput({
        issuer,
        subject,
        cType: cType.$id,
        claims: claims as IClaimContents,
      })

      let loadCTypes: CTypeLoader | false = false
      if (Array.isArray(cTypeDefinitions)) {
        const ctypeMap = new Map<string, ICType>()
        cTypeDefinitions.forEach((ct) => ctypeMap.set(ct.$id, ct))
        loadCTypes = (id) => {
          const definition = ctypeMap.get(id)
          if (typeof definition !== 'undefined') {
            return Promise.resolve(definition)
          }
          return Promise.reject(new SDKErrors.CTypeError(`unknown CType ${id}`))
        }
      } else if (typeof cTypeDefinitions === 'function') {
        loadCTypes = cTypeDefinitions
      }

      await KiltCredentialV1.validateSubject(credential, {
        cTypes: [cType],
        loadCTypes,
      })

      return credential
    }
    default:
      throw new SDKErrors.SDKError(
        `Only credential type ${KiltCredentialV1.CREDENTIAL_TYPE} is currently supported.`
      )
  }
}

/**
 * Issues a Verifiable Credential from on the input document by attaching a proof. Edits to the document may be made depending on the proof type.
 *
 * @param params Holds all named parameters.
 * @param params.credential A credential document as returned by {@link createCredential}.
 * @param params.issuer Interfaces for interacting with the issuer identity for the purpose of generating a proof.
 * @param params.issuer.didDocument The DID Document of the issuer.
 * @param params.issuer.signers An array of signer interfaces, each allowing to request signatures made with a key associated with the issuer DID Document.
 * The function will select the first signer that matches requirements around signature algorithm and relationship of the key to the DID as given by the DID Document.
 * @param params.issuer.submitter Some proof types require making transactions to effect state changes on the KILT blockchain.
 * The blockchain account whose address is specified here will be used to cover all transaction fees and deposits due for this operation.
 * As transactions to the blockchain need to be signed, `signers` is expected to contain a signer interface where the `id` matches this address.
 *
 * Alternatively, you can pass a {@link SubmitOverride} callback that takes care of Did-authorizing and submitting the transaction.
 * If you are using a service that helps you submit and pay for transactions, this is your point of integration to it.
 * @param params.proofOptions Options that control proof generation.
 * @param params.proofOptions.proofType The type of proof to be created.
 * Defaults to {@link KiltAttestationProofV1.PROOF_TYPE KiltAttestationProofV1} which, as of now, is the only type suppported.
 */
export async function issue({
  credential,
  issuer,
  proofOptions = {},
}: {
  credential: UnsignedVc
  issuer: IssuerOptions
  proofOptions?: {
    proofType?: string
  }
}): Promise<VerifiableCredential> {
  const { proofType } = proofOptions
  switch (proofType) {
    case undefined:
    case KiltAttestationProofV1.PROOF_TYPE: {
      const cred = await KiltAttestationProofV1.issue(
        credential as KiltCredentialV1.Interface,
        issuer
      )

      return cred
    }
    default:
      throw new SDKErrors.SDKError(
        `Only proof type ${KiltAttestationProofV1.PROOF_TYPE} is currently supported.`
      )
  }
}

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

    console.log(didDocument)

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

    const response = (await KiltChain.Blockchain.signAndSubmitTx(
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
