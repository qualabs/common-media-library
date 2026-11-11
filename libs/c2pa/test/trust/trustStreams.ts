import { computeBmffHash } from '../../src/bmff/computeBmffHash.ts'
import { encodeCbor } from '../cborTestUtils.ts'
import { buildBox, concatBytes } from '../merkle/merkleTestUtils.ts'
import { createChainSigner, type TestSigner } from '../testSigner.ts'
import {
	buildInitBmffHashAssertion,
	buildSessionKeysAssertion,
	buildSignedInitSegment,
	createTestSessionKey,
	type TestSessionKey,
} from '../vsi/vsiTestUtils.ts'
import { loadDer } from './trustFixtures.ts'

const TEXT_ENCODER = new TextEncoder()
const UUID_EXCLUSIONS = [{ xpath: '/uuid' }]

/** Signer for the `leaf-ec` fixture, with `intermediate-ec` in its `x5chain`. */
export async function createFixtureSigner(): Promise<
	TestSigner & { readonly chain: readonly Uint8Array[] }
> {
	const privateKey = await crypto.subtle.importKey(
		'pkcs8',
		loadDer('leaf-ec.key') as Uint8Array<ArrayBuffer>,
		{ name: 'ECDSA', namedCurve: 'P-256' },
		false,
		['sign'],
	)
	const chain = [loadDer('leaf-ec'), loadDer('intermediate-ec')]
	return {
		chain,
		certificateDER: chain[0],
		issuer: 'CML Trust Leaf EC',
		...createChainSigner(privateKey, chain),
	}
}

export type VsiStream = {
	readonly init: Uint8Array
	readonly sessionKey: TestSessionKey
}

/** Init segment with one session key, with a fresh key ID, bound to the certificate of `signer`. */
export async function buildVsiInitSegment(signer: TestSigner): Promise<VsiStream> {
	const sessionKey = await createTestSessionKey(crypto.randomUUID())
	const init = await buildSignedInitSegment(signer, [
		await buildInitBmffHashAssertion(),
		await buildSessionKeysAssertion(signer, [
			{
				key: sessionKey,
				minSequenceNumber: 0,
				createdAt: new Date(Date.now() - 1000).toISOString(),
				validityPeriod: 3600,
			},
		]),
	])
	return { init, sessionKey }
}

/** ManifestBox live segment signed by `signer`, with a matching flat hash and live-video assertion. */
export async function buildManifestBoxSegment(
	signer: TestSigner,
	sequenceNumber: number,
): Promise<Uint8Array> {
	const media = concatBytes(
		buildBox('moof'),
		buildBox('mdat', TEXT_ENCODER.encode('media payload')),
	)
	const hash = await computeBmffHash(media, { exclusions: UUID_EXCLUSIONS, offsetPrefixSize: 8 })
	return buildSignedInitSegment(
		signer,
		[
			{
				label: 'c2pa.livevideo.segment',
				cbor: encodeCbor({
					sequenceNumber,
					previousManifestId: 'urn:uuid:trust-test-previous',
					streamId: 'stream-1',
					continuityMethod: 'c2pa.manifestId',
				}),
			},
			{
				label: 'c2pa.hash.bmff.v3',
				cbor: encodeCbor({ exclusions: UUID_EXCLUSIONS, alg: 'sha256', hash }),
			},
		],
		media,
	)
}
