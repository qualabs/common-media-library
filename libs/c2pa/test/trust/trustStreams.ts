import { Encoder, encode } from 'cbor-x/encode'
import { computeBmffHash } from '../../src/bmff/computeBmffHash.ts'
import { buildSigStructure } from '../../src/cose/buildSigStructure.ts'
import { JUMBF_UUID } from '../../src/utils.ts'
import { buildBox, buildInitMediaBoxes, buildJumb, buildUuidBox, concatBytes } from '../merkle/merkleTestUtils.ts'
import { createChainSigner, type TestSigner } from '../testSigner.ts'
import { loadDer } from './trustFixtures.ts'

type Signer = Pick<TestSigner, 'sign'>

const TEXT_ENCODER = new TextEncoder()
const CBOR = new Encoder({ tagUint8Array: false, useRecords: false, mapsAsObjects: false })
const COSE_SIGN1_TAG = 0xd2
const ES256 = { name: 'ECDSA', hash: 'SHA-256' }
const MANIFEST_ID = 'urn:uuid:trust-test-manifest'
const EMSG_EXCLUSIONS = [{ xpath: '/emsg' }]
const UUID_EXCLUSIONS = [{ xpath: '/uuid' }]

/** Signer for the `leaf-ec` fixture, with `intermediate-ec` in its `x5chain`. */
export async function createFixtureSigner(): Promise<Signer & { readonly chain: readonly Uint8Array[] }> {
	const privateKey = await crypto.subtle.importKey('pkcs8', loadDer('leaf-ec.key') as Uint8Array<ArrayBuffer>, { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign'])
	const chain = [loadDer('leaf-ec'), loadDer('intermediate-ec')]
	return { chain, ...createChainSigner(privateKey, chain) }
}

async function signCose(privateKey: CryptoKey, protectedHeader: Map<number, unknown>, payload: Uint8Array, attach: boolean): Promise<Uint8Array> {
	const protectedBytes = Uint8Array.from(CBOR.encode(protectedHeader))
	const signature = new Uint8Array(await crypto.subtle.sign(ES256, privateKey, buildSigStructure(protectedBytes, payload) as Uint8Array<ArrayBuffer>))
	const coseSign1 = Uint8Array.from(CBOR.encode([protectedBytes, new Map(), attach ? payload : null, signature]))
	return concatBytes(new Uint8Array([COSE_SIGN1_TAG]), coseSign1)
}

async function buildManifestUuidBox(assertions: Readonly<Record<string, unknown>>, signer: Signer): Promise<Uint8Array> {
	const assertionBoxes = Object.entries(assertions).map(([label, data]) =>
		buildJumb(label, buildBox('cbor', Uint8Array.from(CBOR.encode(data)))))
	const claimCborBytes = Uint8Array.from(CBOR.encode({ instanceID: MANIFEST_ID, created_assertions: [] }))
	const manifest = buildJumb(MANIFEST_ID,
		buildJumb('c2pa.claim', buildBox('cbor', claimCborBytes)),
		buildJumb('c2pa.assertions', ...assertionBoxes),
		buildJumb('c2pa.signature', buildBox('cbor', await signer.sign(claimCborBytes))),
	)
	const purpose = TEXT_ENCODER.encode('manifest')
	const prefix = new Uint8Array(4 + purpose.length + 1 + 8)
	prefix.set(purpose, 4)
	return buildUuidBox(JUMBF_UUID, concatBytes(prefix, buildJumb('c2pa', manifest)))
}

export type VsiStream = {
	readonly init: Uint8Array
	readonly sessionKey: CryptoKey
	readonly kid: Uint8Array
}

/** Init segment with one session key bound to the leaf certificate of `chain`. */
export async function buildVsiInitSegment(signer: Signer, leafCertificate: Uint8Array): Promise<VsiStream> {
	const keyPair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
	const jwk = await crypto.subtle.exportKey('jwk', keyPair.publicKey)
	const coseKey = new Map<number, unknown>([
		[1, 2],
		[-1, 1],
		[-2, new Uint8Array(Buffer.from(jwk.x as string, 'base64url'))],
		[-3, new Uint8Array(Buffer.from(jwk.y as string, 'base64url'))],
	])
	const kid = crypto.getRandomValues(new Uint8Array(16))
	const signerBinding = await signCose(keyPair.privateKey, new Map([[1, -7]]), encode(leafCertificate) as Uint8Array, false)

	const init = concatBytes(buildInitMediaBoxes(), await buildManifestUuidBox({
		'c2pa.session-keys': {
			keys: [{
				key: coseKey,
				kid,
				minSequenceNumber: 0,
				validityPeriod: 3600,
				createdAt: new Date(Date.now() - 1000).toISOString(),
				signerBinding,
			}],
		},
	}, signer))
	return { init, sessionKey: keyPair.privateKey, kid }
}

function buildEmsgBox(messageData: Uint8Array): Uint8Array {
	const schemeAndValue = TEXT_ENCODER.encode('urn:c2pa:verifiable-segment-info\0\0')
	const timingFields = new Uint8Array(16)
	return buildBox('emsg', concatBytes(new Uint8Array(4), schemeAndValue, timingFields, messageData))
}

/** Media segment signed with the session key of `stream`, carrying a VSI `emsg` box after the media boxes. */
export async function buildVsiSegment(stream: VsiStream, sequenceNumber: number, mediaSeed: number): Promise<Uint8Array> {
	const media = concatBytes(buildBox('moof'), buildBox('mdat', new Uint8Array([mediaSeed, mediaSeed + 1])))
	const hash = await computeBmffHash(media, { exclusions: EMSG_EXCLUSIONS, offsetPrefixSize: 8 })
	const vsi = Uint8Array.from(CBOR.encode({
		sequenceNumber,
		bmffHash: { hash, alg: 'sha256', exclusions: EMSG_EXCLUSIONS },
		manifestId: MANIFEST_ID,
	}))
	const cose = await signCose(stream.sessionKey, new Map<number, unknown>([[1, -7], [4, stream.kid]]), vsi, true)
	return concatBytes(media, buildEmsgBox(cose))
}

/** ManifestBox live segment signed by `signer`, with a matching flat hash and live-video assertion. */
export async function buildManifestBoxSegment(signer: Signer, sequenceNumber: number): Promise<Uint8Array> {
	const media = concatBytes(buildBox('moof'), buildBox('mdat', TEXT_ENCODER.encode('media payload')))
	const hash = await computeBmffHash(media, { exclusions: UUID_EXCLUSIONS, offsetPrefixSize: 8 })
	return concatBytes(media, await buildManifestUuidBox({
		'c2pa.livevideo.segment': {
			sequenceNumber,
			previousManifestId: 'urn:uuid:trust-test-previous',
			streamId: 'stream-1',
			continuityMethod: 'c2pa.manifestId',
		},
		'c2pa.hash.bmff.v3': { exclusions: UUID_EXCLUSIONS, alg: 'sha256', hash },
	}, signer))
}
