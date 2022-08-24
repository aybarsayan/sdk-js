/**
 * Copyright (c) 2018-2022, BOTLabs GmbH.
 *
 * This source code is licensed under the BSD 4-Clause "Original" license
 * found in the LICENSE file in the root directory of this source tree.
 */

/**
 * @group unit/messaging
 */

import type {
  CompressedAttestation,
  CompressedDelegationData,
  CompressedInformCreateDelegation,
  CompressedInformDelegationCreation,
  CompressedMessageBody,
  CompressedPartialClaim,
  CompressedQuoteAgreed,
  CompressedQuoteAttesterSigned,
  CompressedRejectAcceptDelegation,
  CompressedRejectedTerms,
  CompressedRejectTerms,
  CompressedRequestAcceptDelegation,
  CompressedRequestAttestation,
  CompressedRequestAttestationContent,
  CompressedRequestCredentialContent,
  CompressedRequestCredentials,
  CompressedRequestDelegationApproval,
  CompressedCredential,
  CompressedRequestTerms,
  CompressedSubmitAcceptDelegation,
  CompressedSubmitAttestation,
  CompressedSubmitCredentials,
  CompressedSubmitDelegationApproval,
  CompressedSubmitTerms,
  CompressedTerms,
  DidDetails,
  DidResolvedDetails,
  DidResourceUri,
  DidUri,
  IAcceptCredential,
  IAttestation,
  IClaim,
  ICType,
  IDelegationData,
  IDidResolver,
  IInformCreateDelegation,
  IInformDelegationCreation,
  IMessage,
  IQuote,
  IQuoteAgreement,
  IQuoteAttesterSigned,
  IRejectAcceptDelegation,
  IRejectAttestation,
  IRejectCredential,
  IRejectTerms,
  IRequestAcceptDelegation,
  IRequestAttestation,
  IRequestAttestationContent,
  IRequestCredential,
  IRequestCredentialContent,
  IRequestDelegationApproval,
  ICredential,
  IRequestTerms,
  ISubmitAcceptDelegation,
  ISubmitAttestation,
  ISubmitAttestationContent,
  ISubmitCredential,
  ISubmitDelegationApproval,
  ISubmitTerms,
  ITerms,
  MessageBody,
  PartialClaim,
  ResolvedDidKey,
} from '@kiltprotocol/types'
import { Crypto, SDKErrors } from '@kiltprotocol/utils'
import {
  Attestation,
  Claim,
  Credential,
  CType,
  Quote,
} from '@kiltprotocol/core'
import * as Did from '@kiltprotocol/did'
import {
  createLocalDemoFullDidFromKeypair,
  KeyTool,
  makeSigningKeyTool,
} from '@kiltprotocol/testing'

import * as MessageUtils from './Message.utils'
import { Message } from './Message'

// TODO: Duplicated code, would be nice to have as a seperated test package with similar helpers
async function buildCredential(
  claimerDid: DidUri,
  attesterDid: DidUri,
  contents: IClaim['contents'],
  legitimations: ICredential[]
): Promise<[ICredential, IAttestation]> {
  // create claim

  const rawCType: ICType['schema'] = {
    $id: Crypto.hashStr('kilt:ctype:0x1'),
    $schema: 'http://kilt-protocol.org/draft-01/ctype#',
    title: 'Credential',
    properties: {
      name: { type: 'string' },
    },
    type: 'object',
  }

  const testCType = CType.fromSchema(rawCType)

  const claim = Claim.fromCTypeAndClaimContents(testCType, contents, claimerDid)
  // build credential with legitimations
  const credential = Credential.fromClaim(claim, {
    legitimations,
  })
  // build attestation
  const testAttestation = Attestation.fromCredentialAndDid(
    credential,
    attesterDid
  )
  return [credential, testAttestation]
}

describe('Messaging Utilities', () => {
  let identityAlice: DidDetails
  let keyAlice: KeyTool

  let identityBob: DidDetails
  let keyBob: KeyTool

  let mockResolver: IDidResolver
  let date: string
  let rawCType: ICType['schema']
  let rawCTypeWithMultipleProperties: ICType['schema']
  let testCType: ICType
  let testCTypeWithMultipleProperties: ICType
  let claim: IClaim
  let claimContents: IClaim['contents']
  let quoteData: IQuote
  let quoteAttesterSigned: IQuoteAttesterSigned
  let bothSigned: IQuoteAgreement
  let compressedLegitimation: CompressedCredential
  let compressedResultAttesterSignedQuote: CompressedQuoteAttesterSigned
  let legitimation: ICredential
  let compressedQuoteAgreement: CompressedQuoteAgreed
  let requestTermsBody: IRequestTerms
  let requestTermsContent: PartialClaim
  let compressedRequestTermsBody: CompressedRequestTerms
  let compressedRequestTermsContent: CompressedPartialClaim
  let submitTermsBody: ISubmitTerms
  let submitTermsContent: ITerms
  let compressedSubmitTermsBody: CompressedSubmitTerms
  let compressedSubmitTermsContent: CompressedTerms
  let rejectTermsBody: IRejectTerms
  let rejectTermsContent: Pick<
    ITerms,
    'claim' | 'legitimations' | 'delegationId'
  >
  let compressedRejectTermsBody: CompressedRejectTerms
  let compressedRejectTermsContent: CompressedRejectedTerms
  let requestAttestationBody: IRequestAttestation
  let requestAttestationContent: IRequestAttestationContent
  let compressedRequestAttestationBody: CompressedRequestAttestation
  let compressedRequestAttestationContent: CompressedRequestAttestationContent
  let submitAttestationContent: ISubmitAttestationContent
  let submitAttestationBody: ISubmitAttestation
  let compressedSubmitAttestationContent: CompressedAttestation
  let compressedSubmitAttestationBody: CompressedSubmitAttestation
  let rejectAttestationForClaimBody: IRejectAttestation
  let requestCredentialBody: IRequestCredential
  let requestCredentialContent: IRequestCredentialContent
  let compressedRequestCredentialBody: CompressedRequestCredentials
  let compressedRequestCredentialContent: CompressedRequestCredentialContent
  let submitCredentialBody: ISubmitCredential
  let submitCredentialContent: ICredential[]
  let acceptCredentialBody: IAcceptCredential
  let compressedSubmitCredentialBody: CompressedSubmitCredentials
  let compressedSubmitCredentialContent: CompressedCredential[]
  let rejectCredentialBody: IRejectCredential
  let requestAcceptDelegationBody: IRequestAcceptDelegation
  let requestAcceptDelegationContent: IRequestDelegationApproval
  let compressedRequestAcceptDelegationBody: CompressedRequestAcceptDelegation
  let compressedRequestAcceptDelegationContent: CompressedRequestDelegationApproval
  let submitAcceptDelegationBody: ISubmitAcceptDelegation
  let submitAcceptDelegationContent: ISubmitDelegationApproval
  let compressedSubmitAcceptDelegationBody: CompressedSubmitAcceptDelegation
  let compressedSubmitAcceptDelegationContent: CompressedSubmitDelegationApproval
  let rejectAcceptDelegationBody: IRejectAcceptDelegation
  let rejectAcceptDelegationContent: IDelegationData
  let compressedRejectAcceptDelegationBody: CompressedRejectAcceptDelegation
  let compressedRejectAcceptDelegationContent: CompressedDelegationData
  let informCreateDelegationBody: IInformCreateDelegation
  let informCreateDelegationContent: IInformDelegationCreation
  let compressedInformCreateDelegationBody: CompressedInformCreateDelegation
  let compressedInformCreateDelegationContent: CompressedInformDelegationCreation
  let messageRequestTerms: IMessage
  let messageSubmitTerms: IMessage
  let messageRejectTerms: IMessage
  let messageRequestAttestationForClaim: IMessage
  let messageSubmitAttestationForClaim: IMessage
  let messageRequestCredential: IMessage
  let messageRejectAttestationForClaim: IMessage
  let messageSubmitCredential: IMessage
  let messageAcceptCredential: IMessage
  let messageRejectCredential: IMessage
  let messageRequestAcceptDelegation: IMessage
  let messageSubmitAcceptDelegation: IMessage
  let messageRejectAcceptDelegation: IMessage
  let messageInformCreateDelegation: IMessage

  beforeAll(async () => {
    keyAlice = makeSigningKeyTool()
    identityAlice = await createLocalDemoFullDidFromKeypair(keyAlice.keypair)
    keyBob = makeSigningKeyTool()
    identityBob = await createLocalDemoFullDidFromKeypair(keyBob.keypair)

    date = new Date(2019, 11, 10).toISOString()
    claimContents = {
      name: 'Bob',
    }

    const resolveDoc = async (
      didUri: DidUri
    ): Promise<DidResolvedDetails | null> => {
      if (didUri === identityAlice.uri) {
        return {
          metadata: {
            deactivated: false,
          },
          details: identityAlice,
        }
      }
      if (didUri === identityBob.uri) {
        return {
          metadata: {
            deactivated: false,
          },
          details: identityBob,
        }
      }
      return null
    }

    const resolveKey = async (
      keyUri: DidResourceUri
    ): Promise<ResolvedDidKey | null> => {
      const { fragment } = Did.Utils.parseDidUri(keyUri)
      const didSubject = keyUri.replace(fragment!, '')
      if (didSubject === identityAlice.uri) {
        const aliceKey = Did.getKey(identityAlice, fragment!)
        if (aliceKey) {
          return {
            id: keyUri,
            controller: didSubject,
            publicKey: aliceKey.publicKey,
            type: aliceKey.type,
          }
        }
        return null
      }
      if (didSubject === identityBob.uri) {
        const bobKey = Did.getKey(identityBob, fragment!)
        if (bobKey) {
          return {
            id: keyUri,
            controller: didSubject,
            publicKey: bobKey.publicKey,
            type: bobKey.type,
          }
        }
        return null
      }
      return null
    }

    mockResolver = {
      resolveDoc,
      resolveKey,
      resolve: async (did: string) =>
        (await resolveKey(did as DidResourceUri)) || resolveDoc(did as DidUri),
    } as IDidResolver

    rawCTypeWithMultipleProperties = {
      $id: Crypto.hashStr('kilt:ctype:0x2'),
      $schema: 'http://kilt-protocol.org/draft-01/ctype#',
      title: 'Drivers license Claim',
      properties: {
        name: { type: 'string' },
        id: { type: 'string' },
        age: { type: 'string' },
      },
      type: 'object',
    }
    // CType Schema
    rawCType = {
      $id: Crypto.hashStr('kilt:ctype:0x1'),
      $schema: 'http://kilt-protocol.org/draft-01/ctype#',
      title: 'ClaimCtype',
      properties: {
        name: { type: 'string' },
      },
      type: 'object',
    }
    // CType
    testCType = CType.fromSchema(rawCType, identityAlice.uri)
    testCTypeWithMultipleProperties = CType.fromSchema(
      rawCTypeWithMultipleProperties,
      identityAlice.uri
    )

    // Claim
    claim = Claim.fromCTypeAndClaimContents(
      testCType,
      claimContents,
      identityAlice.uri
    )
    // Legitimation
    ;[legitimation] = await buildCredential(
      identityAlice.uri,
      identityBob.uri,
      {},
      []
    )
    // Compressed Legitimation
    compressedLegitimation = [
      [
        legitimation.claim.cTypeHash,
        legitimation.claim.owner,
        legitimation.claim.contents,
      ],
      legitimation.claimNonceMap,
      legitimation.claimerSignature,
      legitimation.claimHashes,
      legitimation.rootHash,
      [],
      legitimation.delegationId,
    ]
    // Quote Data
    quoteData = {
      attesterDid: identityAlice.uri,
      cTypeHash: claim.cTypeHash,
      cost: {
        tax: { vat: 3.3 },
        net: 23.4,
        gross: 23.5,
      },
      currency: 'Euro',
      termsAndConditions: 'https://coolcompany.io/terms.pdf',
      timeframe: date,
    }
    // Quote signed by attester
    quoteAttesterSigned = await Quote.createAttesterSignedQuote(
      quoteData,
      identityAlice,
      keyAlice.sign
    )
    // Compressed Quote Attester Signed quote
    compressedResultAttesterSignedQuote = [
      quoteAttesterSigned.attesterDid,
      quoteAttesterSigned.cTypeHash,
      [
        quoteAttesterSigned.cost.gross,
        quoteAttesterSigned.cost.net,
        quoteAttesterSigned.cost.tax,
      ],
      quoteAttesterSigned.currency,
      quoteAttesterSigned.termsAndConditions,
      quoteAttesterSigned.timeframe,
      [
        quoteAttesterSigned.attesterSignature.signature,
        quoteAttesterSigned.attesterSignature.keyUri,
      ],
    ]
    // Quote agreement
    bothSigned = await Quote.createQuoteAgreement(
      quoteAttesterSigned,
      legitimation.rootHash,
      identityAlice.uri,
      identityBob,
      keyBob.sign,
      {
        resolver: mockResolver,
      }
    )
    // Compressed Quote Agreement
    compressedQuoteAgreement = [
      bothSigned.attesterDid,
      bothSigned.cTypeHash,
      [bothSigned.cost.gross, bothSigned.cost.net, bothSigned.cost.tax],
      bothSigned.currency,
      bothSigned.termsAndConditions,
      bothSigned.timeframe,
      [
        bothSigned.attesterSignature.signature,
        bothSigned.attesterSignature.keyUri,
      ],
      [
        bothSigned.claimerSignature.signature,
        bothSigned.claimerSignature.keyUri,
      ],
      bothSigned.rootHash,
    ]
    // Request Terms content
    requestTermsContent = {
      cTypeHash: claim.cTypeHash,
    }
    // Compressed Request terms content
    compressedRequestTermsContent = [claim.cTypeHash, undefined, undefined]
    // Submit Terms content
    submitTermsContent = {
      claim: {
        cTypeHash: claim.cTypeHash,
      },
      legitimations: [legitimation],
      delegationId: undefined,
      quote: quoteAttesterSigned,
      cTypes: undefined,
    }
    // Compressed Submit Terms Contents
    compressedSubmitTermsContent = [
      compressedRequestTermsContent,
      [compressedLegitimation],
      undefined,
      compressedResultAttesterSignedQuote,
      undefined,
    ]
    // Reject terms Content
    rejectTermsContent = {
      claim: {
        cTypeHash: claim.cTypeHash,
      },
      legitimations: [legitimation],
    }
    // Compressed Reject terms content
    compressedRejectTermsContent = [
      compressedRequestTermsContent,
      [compressedLegitimation],
      undefined,
    ]

    // Request Attestation Content
    requestAttestationContent = {
      credential: legitimation,
      quote: bothSigned,
    }

    // Compressed Request attestation content
    compressedRequestAttestationContent = [
      [
        [
          legitimation.claim.cTypeHash,
          legitimation.claim.owner,
          legitimation.claim.contents,
        ],
        legitimation.claimNonceMap,
        legitimation.claimerSignature,
        legitimation.claimHashes,
        legitimation.rootHash,
        [],
        legitimation.delegationId,
      ],
      compressedQuoteAgreement,
    ]

    // Submit Attestation content
    submitAttestationContent = {
      attestation: {
        delegationId: null,
        claimHash: requestAttestationContent.credential.rootHash,
        cTypeHash: claim.cTypeHash,
        owner: identityBob.uri,
        revoked: false,
      },
    }

    // Compressed Submit Attestation content
    compressedSubmitAttestationContent = [
      submitAttestationContent.attestation.claimHash,
      submitAttestationContent.attestation.cTypeHash,
      submitAttestationContent.attestation.owner,
      submitAttestationContent.attestation.revoked,
      submitAttestationContent.attestation.delegationId,
    ]
    // Request Credential content
    requestCredentialContent = {
      cTypes: [
        {
          cTypeHash: claim.cTypeHash,
          trustedAttesters: [identityAlice.uri],
          requiredProperties: ['id', 'name'],
        },
      ],
      challenge: '1234',
    }
    // Compressed Request Credential content
    compressedRequestCredentialContent = [
      [[claim.cTypeHash, [identityAlice.uri], ['id', 'name']]],
      '1234',
    ]
    // Submit Credential content
    submitCredentialContent = [legitimation]
    // Compressed Submit Credential content
    compressedSubmitCredentialContent = [compressedLegitimation]
    // Request Accept delegation content
    requestAcceptDelegationContent = {
      delegationData: {
        account: identityAlice.uri,
        id: Crypto.hashStr('0x12345678'),
        parentId: Crypto.hashStr('0x12345678'),
        permissions: [1],
        isPCR: false,
      },
      metaData: {},
      signatures: {
        inviter: await Did.signPayload(
          identityAlice,
          'signature',
          keyAlice.sign,
          identityAlice.authentication[0].id
        ),
      },
    }
    // Compressed Request accept delegation content
    compressedRequestAcceptDelegationContent = [
      [
        requestAcceptDelegationContent.delegationData.account,
        requestAcceptDelegationContent.delegationData.id,
        requestAcceptDelegationContent.delegationData.parentId,
        requestAcceptDelegationContent.delegationData.permissions,
        requestAcceptDelegationContent.delegationData.isPCR,
      ],
      [
        requestAcceptDelegationContent.signatures.inviter.signature,
        requestAcceptDelegationContent.signatures.inviter.keyUri,
      ],
      requestAcceptDelegationContent.metaData,
    ]
    // Submit Accept delegation content
    submitAcceptDelegationContent = {
      delegationData: {
        account: identityAlice.uri,
        id: Crypto.hashStr('0x12345678'),
        parentId: Crypto.hashStr('0x12345678'),
        permissions: [1],
        isPCR: false,
      },
      signatures: {
        inviter: await Did.signPayload(
          identityAlice,
          'signature',
          keyAlice.sign,
          identityAlice.authentication[0].id
        ),
        invitee: await Did.signPayload(
          identityBob,
          'signature',
          keyBob.sign,
          identityBob.authentication[0].id
        ),
      },
    }
    // Compressed Submit accept delegation content
    compressedSubmitAcceptDelegationContent = [
      [
        submitAcceptDelegationContent.delegationData.account,
        submitAcceptDelegationContent.delegationData.id,
        submitAcceptDelegationContent.delegationData.parentId,
        submitAcceptDelegationContent.delegationData.permissions,
        submitAcceptDelegationContent.delegationData.isPCR,
      ],
      [
        submitAcceptDelegationContent.signatures.inviter.signature,
        submitAcceptDelegationContent.signatures.inviter.keyUri,
      ],
      [
        submitAcceptDelegationContent.signatures.invitee.signature,
        submitAcceptDelegationContent.signatures.invitee.keyUri,
      ],
    ]
    // Reject Accept Delegation content
    rejectAcceptDelegationContent = {
      account: identityAlice.uri,
      id: Crypto.hashStr('0x12345678'),
      parentId: Crypto.hashStr('0x12345678'),
      permissions: [1],
      isPCR: false,
    }
    // Compressed Reject accept delegation content
    compressedRejectAcceptDelegationContent = [
      rejectAcceptDelegationContent.account,
      rejectAcceptDelegationContent.id,
      rejectAcceptDelegationContent.parentId,
      rejectAcceptDelegationContent.permissions,
      rejectAcceptDelegationContent.isPCR,
    ]

    informCreateDelegationContent = {
      delegationId: Crypto.hashStr('0x12345678'),
      isPCR: false,
    }

    compressedInformCreateDelegationContent = [
      informCreateDelegationContent.delegationId,
      informCreateDelegationContent.isPCR,
    ]

    requestTermsBody = {
      content: requestTermsContent,
      type: 'request-terms',
    }

    compressedRequestTermsBody = [
      'request-terms',
      compressedRequestTermsContent,
    ]

    submitTermsBody = {
      content: submitTermsContent,
      type: 'submit-terms',
    }

    compressedSubmitTermsBody = ['submit-terms', compressedSubmitTermsContent]

    rejectTermsBody = {
      content: rejectTermsContent,
      type: 'reject-terms',
    }

    compressedRejectTermsBody = ['reject-terms', compressedRejectTermsContent]

    requestAttestationBody = {
      content: requestAttestationContent,
      type: 'request-attestation',
    }

    compressedRequestAttestationBody = [
      'request-attestation',
      compressedRequestAttestationContent,
    ]

    submitAttestationBody = {
      content: submitAttestationContent,
      type: 'submit-attestation',
    }

    compressedSubmitAttestationBody = [
      'submit-attestation',
      compressedSubmitAttestationContent,
    ]

    rejectAttestationForClaimBody = {
      content: requestAttestationContent.credential.rootHash,
      type: 'reject-attestation',
    }
    requestCredentialBody = {
      content: requestCredentialContent,
      type: 'request-credential',
    }

    compressedRequestCredentialBody = [
      'request-credential',
      compressedRequestCredentialContent,
    ]

    submitCredentialBody = {
      content: submitCredentialContent,
      type: 'submit-credential',
    }

    compressedSubmitCredentialBody = [
      'submit-credential',
      compressedSubmitCredentialContent,
    ]

    acceptCredentialBody = {
      content: [claim.cTypeHash],
      type: 'accept-credential',
    }

    rejectCredentialBody = {
      content: [claim.cTypeHash],
      type: 'reject-credential',
    }

    requestAcceptDelegationBody = {
      content: requestAcceptDelegationContent,
      type: 'request-accept-delegation',
    }

    compressedRequestAcceptDelegationBody = [
      'request-accept-delegation',
      compressedRequestAcceptDelegationContent,
    ]

    submitAcceptDelegationBody = {
      content: submitAcceptDelegationContent,
      type: 'submit-accept-delegation',
    }

    compressedSubmitAcceptDelegationBody = [
      'submit-accept-delegation',
      compressedSubmitAcceptDelegationContent,
    ]

    rejectAcceptDelegationBody = {
      content: rejectAcceptDelegationContent,
      type: 'reject-accept-delegation',
    }

    compressedRejectAcceptDelegationBody = [
      'reject-accept-delegation',
      compressedRejectAcceptDelegationContent,
    ]

    informCreateDelegationBody = {
      content: informCreateDelegationContent,
      type: 'inform-create-delegation',
    }

    compressedInformCreateDelegationBody = [
      'inform-create-delegation',
      compressedInformCreateDelegationContent,
    ]
  })

  it('Checking message compression and decompression Terms', async () => {
    // Request compression of terms body
    expect(MessageUtils.compressMessage(requestTermsBody)).toEqual(
      compressedRequestTermsBody
    )
    // Request decompression of terms body
    expect(MessageUtils.decompressMessage(compressedRequestTermsBody)).toEqual(
      requestTermsBody
    )
    // Submit compression of terms body
    expect(MessageUtils.compressMessage(submitTermsBody)).toEqual(
      compressedSubmitTermsBody
    )
    // Submit decompression of terms body
    expect(MessageUtils.decompressMessage(compressedSubmitTermsBody)).toEqual(
      submitTermsBody
    )
    // Reject compression of terms body
    expect(MessageUtils.compressMessage(rejectTermsBody)).toEqual(
      compressedRejectTermsBody
    )
    // Reject decompression of terms body
    expect(MessageUtils.decompressMessage(compressedRejectTermsBody)).toEqual(
      rejectTermsBody
    )
  })
  it('Checking message compression and decompression Attestation', async () => {
    // Request compression of attestation body
    expect(MessageUtils.compressMessage(requestAttestationBody)).toEqual(
      compressedRequestAttestationBody
    )
    // Request decompression of attestation body
    expect(
      MessageUtils.decompressMessage(compressedRequestAttestationBody)
    ).toEqual(requestAttestationBody)
    // Submit compression of attestation body

    expect(MessageUtils.compressMessage(submitAttestationBody)).toEqual(
      compressedSubmitAttestationBody
    )
    // Submit decompression of attestation body
    expect(
      MessageUtils.decompressMessage(compressedSubmitAttestationBody)
    ).toEqual(submitAttestationBody)
  })

  it('Checking message compression and decompression Request Credential', async () => {
    // Request compression of credential body
    expect(MessageUtils.compressMessage(requestCredentialBody)).toEqual(
      compressedRequestCredentialBody
    )
    // Request decompression of credential body
    expect(
      MessageUtils.decompressMessage(compressedRequestCredentialBody)
    ).toEqual(requestCredentialBody)
    // Submit compression of credential body
    expect(MessageUtils.compressMessage(submitCredentialBody)).toEqual(
      compressedSubmitCredentialBody
    )
    // Submit decompression of credential body
    expect(
      MessageUtils.decompressMessage(compressedSubmitCredentialBody)
    ).toEqual(submitCredentialBody)
  })
  it('Checking message compression and decompression delegation', async () => {
    // Request compression of delegation body
    expect(MessageUtils.compressMessage(requestAcceptDelegationBody)).toEqual(
      compressedRequestAcceptDelegationBody
    )
    // Request decompression of delegation body
    expect(
      MessageUtils.decompressMessage(compressedRequestAcceptDelegationBody)
    ).toEqual(requestAcceptDelegationBody)
    // Submit compression of delegation body
    expect(MessageUtils.compressMessage(submitAcceptDelegationBody)).toEqual(
      compressedSubmitAcceptDelegationBody
    )
    // Submit decompression of delegation body
    expect(
      MessageUtils.decompressMessage(compressedSubmitAcceptDelegationBody)
    ).toEqual(submitAcceptDelegationBody)
    // Reject compression of delegation body
    expect(MessageUtils.compressMessage(rejectAcceptDelegationBody)).toEqual(
      compressedRejectAcceptDelegationBody
    )
    // Reject decompression of delegation body
    expect(
      MessageUtils.decompressMessage(compressedRejectAcceptDelegationBody)
    ).toEqual(rejectAcceptDelegationBody)
  })
  it('Checking message compression and decompression Inform create delegation', async () => {
    // Inform compression of the create delegation
    expect(MessageUtils.compressMessage(informCreateDelegationBody)).toEqual(
      compressedInformCreateDelegationBody
    )
    // Inform decompression of the create delegation
    expect(
      MessageUtils.decompressMessage(compressedInformCreateDelegationBody)
    ).toEqual(informCreateDelegationBody)
  })
  it('Checks the MessageBody Types through the compress and decompress switch function', async () => {
    const compressedMalformed = ['', []] as unknown as CompressedMessageBody

    expect(() =>
      MessageUtils.decompressMessage(compressedMalformed)
    ).toThrowError(SDKErrors.UnknownMessageBodyTypeError)

    const malformed = {
      content: '',
      type: 'MessageBodyType',
    } as unknown as MessageBody

    expect(() => MessageUtils.compressMessage(malformed)).toThrowError(
      SDKErrors.UnknownMessageBodyTypeError
    )
  })
  it('Checking required properties for given CType', () => {
    expect(() =>
      MessageUtils.verifyRequiredCTypeProperties(['id', 'name'], testCType)
    ).toThrowError(SDKErrors.CTypeUnknownPropertiesError)

    expect(() =>
      MessageUtils.verifyRequiredCTypeProperties(
        ['id', 'name'],
        testCTypeWithMultipleProperties
      )
    ).not.toThrowError(SDKErrors.CTypeUnknownPropertiesError)

    expect(() =>
      MessageUtils.verifyRequiredCTypeProperties(
        ['id', 'name'],
        testCTypeWithMultipleProperties
      )
    ).not.toThrowError()
  })

  beforeAll(async () => {
    messageRequestTerms = new Message(
      requestTermsBody,
      identityAlice.uri,
      identityBob.uri
    )
    messageSubmitTerms = new Message(
      submitTermsBody,
      identityAlice.uri,
      identityBob.uri
    )
    messageRejectTerms = new Message(
      rejectTermsBody,
      identityAlice.uri,
      identityBob.uri
    )
    messageRequestAttestationForClaim = new Message(
      requestAttestationBody,
      identityAlice.uri,
      identityBob.uri
    )
    messageSubmitAttestationForClaim = new Message(
      submitAttestationBody,
      identityAlice.uri,
      identityBob.uri
    )

    messageRejectAttestationForClaim = new Message(
      rejectAttestationForClaimBody,
      identityAlice.uri,
      identityBob.uri
    )
    messageRequestCredential = new Message(
      requestCredentialBody,
      identityAlice.uri,
      identityBob.uri
    )
    messageSubmitCredential = new Message(
      submitCredentialBody,
      identityAlice.uri,
      identityBob.uri
    )
    messageAcceptCredential = new Message(
      acceptCredentialBody,
      identityAlice.uri,
      identityBob.uri
    )
    messageRejectCredential = new Message(
      rejectCredentialBody,
      identityAlice.uri,
      identityBob.uri
    )
    messageRequestAcceptDelegation = new Message(
      requestAcceptDelegationBody,
      identityAlice.uri,
      identityBob.uri
    )
    messageSubmitAcceptDelegation = new Message(
      submitAcceptDelegationBody,
      identityAlice.uri,
      identityBob.uri
    )
    messageRejectAcceptDelegation = new Message(
      rejectAcceptDelegationBody,
      identityAlice.uri,
      identityBob.uri
    )
    messageInformCreateDelegation = new Message(
      informCreateDelegationBody,
      identityAlice.uri,
      identityBob.uri
    )
  })
  it('error check should not throw errors on faulty bodies', () => {
    expect(() =>
      MessageUtils.errorCheckMessageBody(requestTermsBody)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessageBody(submitTermsBody)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessageBody(rejectTermsBody)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessageBody(requestAttestationBody)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessageBody(submitAttestationBody)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessageBody(rejectAttestationForClaimBody)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessageBody(requestCredentialBody)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessageBody(submitCredentialBody)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessageBody(acceptCredentialBody)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessageBody(rejectCredentialBody)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessageBody(requestAcceptDelegationBody)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessageBody(submitAcceptDelegationBody)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessageBody(rejectAcceptDelegationBody)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessageBody(informCreateDelegationBody)
    ).not.toThrowError()
  })
  it('error check should not throw errors on message', () => {
    expect(() =>
      MessageUtils.errorCheckMessage(messageRequestTerms)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessage(messageSubmitTerms)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessage(messageRejectTerms)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessage(messageRequestAttestationForClaim)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessage(messageSubmitAttestationForClaim)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessage(messageRejectAttestationForClaim)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessage(messageRequestCredential)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessage(messageSubmitCredential)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessage(messageAcceptCredential)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessage(messageRejectCredential)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessage(messageRequestAcceptDelegation)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessage(messageSubmitAcceptDelegation)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessage(messageRejectAcceptDelegation)
    ).not.toThrowError()
    expect(() =>
      MessageUtils.errorCheckMessage(messageInformCreateDelegation)
    ).not.toThrowError()
  })
  it('error check should throw errors on message', () => {
    messageRequestTerms.receiver =
      'did:kilt:thisisnotareceiveraddress' as DidUri
    expect(() =>
      MessageUtils.errorCheckMessage(messageRequestTerms)
    ).toThrowError(SDKErrors.InvalidDidFormatError)
    // @ts-ignore
    messageSubmitTerms.sender = 'this is not a sender did'
    expect(() =>
      MessageUtils.errorCheckMessage(messageSubmitTerms)
    ).toThrowError(SDKErrors.InvalidDidFormatError)
    // @ts-ignore
    messageRejectTerms.sender = 'this is not a sender address'
    expect(() =>
      MessageUtils.errorCheckMessage(messageRejectTerms)
    ).toThrowError(SDKErrors.InvalidDidFormatError)
  })
  it('error check should throw errors on faulty bodies', () => {
    // @ts-ignore
    requestTermsBody.content.cTypeHash = 'this is not a ctype hash'
    expect(() =>
      MessageUtils.errorCheckMessageBody(requestTermsBody)
    ).toThrowError(SDKErrors.HashMalformedError)
    submitTermsBody.content.delegationId = 'this is not a delegation id'
    expect(() =>
      MessageUtils.errorCheckMessageBody(submitTermsBody)
    ).toThrowError(SDKErrors.HashMalformedError)

    rejectTermsBody.content.delegationId = 'this is not a delegation id'
    expect(() =>
      MessageUtils.errorCheckMessageBody(rejectTermsBody)
    ).toThrowError(SDKErrors.HashMalformedError)
    // @ts-expect-error
    delete rejectTermsBody.content.claim.cTypeHash
    expect(() =>
      MessageUtils.errorCheckMessageBody(rejectTermsBody)
    ).toThrowError(SDKErrors.CTypeHashMissingError)
    requestAttestationBody.content.credential.claimerSignature = {
      signature: 'this is not the claimers signature',
      // @ts-ignore
      keyUri: 'this is not a key id',
    }
    expect(() =>
      MessageUtils.errorCheckMessageBody(requestAttestationBody)
    ).toThrowError()
    // @ts-ignore
    submitAttestationBody.content.attestation.claimHash =
      'this is not the claim hash'
    expect(() =>
      MessageUtils.errorCheckMessageBody(submitAttestationBody)
    ).toThrowError(SDKErrors.HashMalformedError)
    // @ts-ignore
    rejectAttestationForClaimBody.content = 'this is not the root hash'
    expect(() =>
      MessageUtils.errorCheckMessageBody(rejectAttestationForClaimBody)
    ).toThrowError(SDKErrors.HashMalformedError)
    // @ts-ignore
    requestCredentialBody.content.cTypes[0].cTypeHash =
      'this is not a cTypeHash'
    expect(() =>
      MessageUtils.errorCheckMessageBody(requestCredentialBody)
    ).toThrowError(SDKErrors.HashMalformedError)
    // @ts-ignore
    acceptCredentialBody.content[0] = 'this is not a cTypeHash'
    expect(() =>
      MessageUtils.errorCheckMessageBody(acceptCredentialBody)
    ).toThrowError(SDKErrors.HashMalformedError)
    // @ts-ignore
    rejectCredentialBody.content[0] = 'this is not a cTypeHash'
    expect(() =>
      MessageUtils.errorCheckMessageBody(rejectCredentialBody)
    ).toThrowError(SDKErrors.HashMalformedError)
    delete requestAcceptDelegationBody.content.metaData
    expect(() =>
      MessageUtils.errorCheckMessageBody(requestAcceptDelegationBody)
    ).toThrowError(SDKErrors.ObjectUnverifiableError)
    requestAcceptDelegationBody.content.signatures.inviter.signature =
      'this is not a signature'
    expect(() =>
      MessageUtils.errorCheckMessageBody(requestAcceptDelegationBody)
    ).toThrowError(SDKErrors.SignatureMalformedError)
    // @ts-ignore
    submitAcceptDelegationBody.content.signatures.invitee.keyUri =
      'this is not a key id'
    expect(() =>
      MessageUtils.errorCheckMessageBody(submitAcceptDelegationBody)
    ).toThrowError(SDKErrors.SignatureMalformedError)
    submitAcceptDelegationBody.content.delegationData.parentId =
      'this is not a parent id hash'
    expect(() =>
      MessageUtils.errorCheckMessageBody(submitAcceptDelegationBody)
    ).toThrowError(SDKErrors.DelegationIdTypeError)
    // @ts-expect-error
    delete rejectAcceptDelegationBody.content.account
    expect(() =>
      MessageUtils.errorCheckMessageBody(rejectAcceptDelegationBody)
    ).toThrowError(SDKErrors.OwnerMissingError)
    informCreateDelegationBody.content.delegationId =
      'this is not a delegation id'
    expect(() =>
      MessageUtils.errorCheckMessageBody(informCreateDelegationBody)
    ).toThrowError(SDKErrors.HashMalformedError)
    expect(() =>
      MessageUtils.errorCheckMessageBody({} as MessageBody)
    ).toThrowError(SDKErrors.UnknownMessageBodyTypeError)
  })
  it('error check of the delegation data in messaging', () => {
    // @ts-expect-error
    delete requestAcceptDelegationBody.content.delegationData.isPCR
    expect(() =>
      MessageUtils.errorCheckDelegationData(
        requestAcceptDelegationBody.content.delegationData
      )
    ).toThrowError(TypeError('isPCR is expected to be a boolean'))
    requestAcceptDelegationBody.content.delegationData.id =
      'this is not a delegation id'
    expect(() =>
      MessageUtils.errorCheckDelegationData(
        requestAcceptDelegationBody.content.delegationData
      )
    ).toThrowError(SDKErrors.DelegationIdTypeError)
    submitAcceptDelegationBody.content.delegationData.permissions = []
    expect(() =>
      MessageUtils.errorCheckDelegationData(
        submitAcceptDelegationBody.content.delegationData
      )
    ).toThrowError(SDKErrors.UnauthorizedError)
    // @ts-expect-error
    delete submitAcceptDelegationBody.content.delegationData.id
    expect(() =>
      MessageUtils.errorCheckDelegationData(
        submitAcceptDelegationBody.content.delegationData
      )
    ).toThrowError(SDKErrors.DelegationIdMissingError)
  })
})
