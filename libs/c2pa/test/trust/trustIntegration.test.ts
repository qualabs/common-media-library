import {
	C2paStatusCode,
	createTrustPolicy,
	validateC2paInitSegment,
	validateC2paManifestBoxSegment,
	validateC2paMerkleSegment,
	validateC2paSegment,
	type TrustPolicy,
	type ValidatedSessionKey,
} from '@svta/cml-c2pa'
import { deepStrictEqual, ok, strictEqual } from 'node:assert'
import { afterEach, before, describe, it, mock } from 'node:test'
import { computeBmffHash } from '../../src/bmff/computeBmffHash.ts'
import {
	buildInitMediaBoxes,
	buildMediaContent,
	buildMerkleAuxBox,
	buildProofPath,
	buildSignedMerkleInitSegment,
	buildTreeLevels,
	concatBytes,
	manifestRow,
} from '../merkle/merkleTestUtils.ts'
import { createTestSigner } from '../testSigner.ts'
import { hashCertificate } from '../../src/trust/evaluateCertificateTrust.ts'
import { loadDer, pem, PKI_PATH } from './trustFixtures.ts'
import { buildManifestBoxSegment, buildVsiInitSegment, buildVsiSegment, createFixtureSigner, type VsiStream } from './trustStreams.ts'

type Scenario = {
	readonly name: string
	readonly isTrusted: boolean
	readonly policy: () => Promise<TrustPolicy>
}

const SCENARIOS: readonly Scenario[] = [
	{ name: 'trust anchor match', isTrusted: true, policy: () => createTrustPolicy({ trustAnchors: pem('root-ec') }) },
	{ name: 'allowed list match', isTrusted: true, policy: async () => createTrustPolicy({ allowedList: `${await hashCertificate(loadDer('leaf-ec'))}\n` }) },
	{ name: 'no match', isTrusted: false, policy: () => createTrustPolicy({ trustAnchors: pem('root-rsa') }) },
	{
		name: 'degraded by URL',
		isTrusted: false,
		policy: async () => {
			mock.method(globalThis, 'fetch', async () => new Response('', { status: 503 }))
			return createTrustPolicy({ trustAnchors: pem('root-ec'), allowedList: 'https://example.com/allowed.txt' })
		},
	},
	{ name: 'degraded by path', isTrusted: false, policy: () => createTrustPolicy({ trustAnchors: `${PKI_PATH}.missing` }) },
]

const SIGNATURE_LABEL = new TextEncoder().encode('c2pa.signature')
const CBOR_BOX_TYPE = new TextEncoder().encode('cbor')

function indexOfBytes(bytes: Uint8Array, pattern: Uint8Array, from = 0): number {
	for (let i = from; i <= bytes.length - pattern.length; i++) {
		if (pattern.every((byte, j) => bytes[i + j] === byte)) return i
	}
	return -1
}

/** Copy of a signed segment whose COSE claim signature no longer verifies. The x5chain is untouched. */
function forgeClaimSignature(segment: Uint8Array): Uint8Array {
	const forged = segment.slice()
	const typeOffset = indexOfBytes(forged, CBOR_BOX_TYPE, indexOfBytes(forged, SIGNATURE_LABEL))
	const boxEnd = typeOffset - 4 + new DataView(forged.buffer).getUint32(typeOffset - 4)
	forged[boxEnd - 1] ^= 0xff
	return forged
}

/** The codes a scenario adds to the result without a policy: none when the signer is trusted. */
function trustCodes(scenario: Scenario): string[] {
	return scenario.isTrusted ? [] : [C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED]
}

const MERKLE_UNIQUE_ID = 3
const MERKLE_EXCLUSIONS = [{ xpath: '/uuid' }]

async function buildMerkleStream(sign: Parameters<typeof buildSignedMerkleInitSegment>[1]): Promise<{ init: Uint8Array; segment: Uint8Array }> {
	const contents = [buildMediaContent(0), buildMediaContent(10)]
	const leaves = await Promise.all(contents.map(c => computeBmffHash(c, { offsetPrefixSize: 8, exclusions: MERKLE_EXCLUSIONS })))
	const levels = await buildTreeLevels(leaves)
	const initHash = await computeBmffHash(buildInitMediaBoxes(), { offsetPrefixSize: 8 })
	const init = await buildSignedMerkleInitSegment({
		exclusions: MERKLE_EXCLUSIONS,
		merkle: [{ uniqueId: MERKLE_UNIQUE_ID, localId: 1, count: 2, hashes: manifestRow(levels, 1), alg: 'SHA-256', initHash }],
	}, sign)
	const segment = concatBytes(contents[0], buildMerkleAuxBox({
		uniqueId: MERKLE_UNIQUE_ID,
		localId: 1,
		location: 0,
		hashes: buildProofPath(levels, 0, 1),
	}))
	return { init, segment }
}

describe('trust across validation paths', () => {
	let signer: Awaited<ReturnType<typeof createFixtureSigner>>
	let vsi: VsiStream
	let vsiSegment: Uint8Array
	let merkle: { init: Uint8Array; segment: Uint8Array }
	let manifestBoxSegment: Uint8Array

	before(async () => {
		signer = await createFixtureSigner()
		vsi = await buildVsiInitSegment(signer, signer.chain[0])
		vsiSegment = await buildVsiSegment(vsi, 1, 5)
		merkle = await buildMerkleStream(signer)
		manifestBoxSegment = await buildManifestBoxSegment(signer, 1)
	})

	afterEach(() => mock.restoreAll())

	// #region example
	it('reports a trusted signer on a VSI stream', async () => {
		const trustPolicy = await createTrustPolicy({ trustAnchors: pem('root-ec') })

		const init = await validateC2paInitSegment(vsi.init, { trustPolicy })
		const segment = await validateC2paSegment(vsiSegment, init.sessionKeys)

		strictEqual(init.isTrusted, true)
		strictEqual(segment?.result.isValid, true)
		strictEqual(segment?.result.isTrusted, true)
	})
	// #endregion example

	it('leaves isTrusted absent without a policy', async () => {
		const init = await validateC2paInitSegment(vsi.init)
		const segment = await validateC2paSegment(vsiSegment, init.sessionKeys)
		const merkleInit = await validateC2paInitSegment(merkle.init)
		const merkleSegment = await validateC2paMerkleSegment(merkle.segment, merkleInit.merkleMaps)
		const manifestBox = await validateC2paManifestBoxSegment(manifestBoxSegment, null)

		strictEqual('isTrusted' in init, false)
		strictEqual('isTrusted' in init.sessionKeys[0], false)
		strictEqual('isTrusted' in (segment?.result ?? {}), false)
		strictEqual('isTrusted' in merkleInit, false)
		strictEqual('isTrusted' in merkleInit.merkleMaps[0], false)
		strictEqual('isTrusted' in merkleSegment.result, false)
		strictEqual('isTrusted' in manifestBox.result, false)
	})

	for (const scenario of SCENARIOS) {
		describe(scenario.name, () => {
			it('VSI: init and segment', async () => {
				const trustPolicy = await scenario.policy()
				const baseline = await validateC2paInitSegment(vsi.init)
				const init = await validateC2paInitSegment(vsi.init, { trustPolicy })
				const segment = await validateC2paSegment(vsiSegment, init.sessionKeys)
				const baselineSegment = await validateC2paSegment(vsiSegment, baseline.sessionKeys)

				strictEqual(baseline.isValid, true)
				strictEqual(baselineSegment?.result.isValid, true)
				strictEqual(init.isTrusted, scenario.isTrusted)
				strictEqual(init.sessionKeys[0].isTrusted, scenario.isTrusted)
				strictEqual(segment?.result.isTrusted, scenario.isTrusted)
				strictEqual(init.isValid, scenario.isTrusted)
				deepStrictEqual(init.errorCodes, [...baseline.errorCodes, ...trustCodes(scenario)])
				strictEqual(segment?.result.isValid, scenario.isTrusted)
				deepStrictEqual(segment?.result.errorCodes, [...(baselineSegment?.result.errorCodes ?? []), ...trustCodes(scenario)])
			})

			it('Merkle: init and segment', async () => {
				const trustPolicy = await scenario.policy()
				const baseline = await validateC2paInitSegment(merkle.init)
				const init = await validateC2paInitSegment(merkle.init, { trustPolicy })
				const segment = await validateC2paMerkleSegment(merkle.segment, init.merkleMaps)
				const baselineSegment = await validateC2paMerkleSegment(merkle.segment, baseline.merkleMaps)

				strictEqual(baseline.isValid, true)
				strictEqual(baselineSegment.result.isValid, true)
				strictEqual(init.isTrusted, scenario.isTrusted)
				strictEqual(init.merkleMaps[0].isTrusted, scenario.isTrusted)
				strictEqual(segment.result.isTrusted, scenario.isTrusted)
				strictEqual(init.isValid, scenario.isTrusted)
				deepStrictEqual(init.errorCodes, [...baseline.errorCodes, ...trustCodes(scenario)])
				strictEqual(segment.result.isValid, scenario.isTrusted)
				deepStrictEqual(segment.result.errorCodes, [...baselineSegment.result.errorCodes, ...trustCodes(scenario)])
			})

			it('ManifestBox: segment', async () => {
				const trustPolicy = await scenario.policy()
				const baseline = await validateC2paManifestBoxSegment(manifestBoxSegment, null)
				const validated = await validateC2paManifestBoxSegment(manifestBoxSegment, null, undefined, { trustPolicy })

				strictEqual(baseline.result.isValid, true)
				strictEqual(validated.result.isTrusted, scenario.isTrusted)
				strictEqual(validated.result.isValid, scenario.isTrusted)
				const { isTrusted: _, isValid: __, errorCodes, ...rest } = validated.result
				const { isValid: ___, errorCodes: baselineCodes, ...baselineRest } = baseline.result
				deepStrictEqual(errorCodes, [...baselineCodes, ...trustCodes(scenario)])
				deepStrictEqual({ ...validated, result: rest }, { ...baseline, result: baselineRest })
			})
		})
	}

	it('reports both an untrusted chain and a claim signature that does not verify', async () => {
		const trustPolicy = await createTrustPolicy({ trustAnchors: pem('root-rsa') })

		const box = await validateC2paManifestBoxSegment(forgeClaimSignature(manifestBoxSegment), null, undefined, { trustPolicy })

		ok(box.result.errorCodes.includes(C2paStatusCode.CLAIM_SIGNATURE_MISMATCH))
		ok(box.result.errorCodes.includes(C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED))
		strictEqual(box.result.isTrusted, false)
	})

	it('rejects a signing certificate without an accepted EKU as an invalid credential', async () => {
		const trustPolicy = await createTrustPolicy({ trustAnchors: pem('root-ec'), trustConfig: '1.3.6.1.4.1.62558.2.1\n' })

		const init = await validateC2paInitSegment(vsi.init, { trustPolicy })
		const box = await validateC2paManifestBoxSegment(manifestBoxSegment, null, undefined, { trustPolicy })

		strictEqual(init.isValid, false)
		ok(init.errorCodes.includes(C2paStatusCode.SIGNING_CREDENTIAL_INVALID))
		strictEqual(box.result.isValid, false)
		ok(box.result.errorCodes.includes(C2paStatusCode.SIGNING_CREDENTIAL_INVALID))
	})

	it('keeps the verdict of the session key when the segment is tampered', async () => {
		const trustPolicy = await createTrustPolicy({ trustAnchors: pem('root-ec') })
		const init = await validateC2paInitSegment(vsi.init, { trustPolicy })
		const tampered = vsiSegment.slice()
		tampered[12] ^= 0xff

		const segment = await validateC2paSegment(tampered, init.sessionKeys)

		strictEqual(segment?.result.isValid, false)
		strictEqual(segment?.result.isTrusted, true)
	})

	it('does not trust a signer whose claim signature does not verify', async () => {
		const trustPolicy = await createTrustPolicy({ trustAnchors: pem('root-ec') })

		const box = await validateC2paManifestBoxSegment(forgeClaimSignature(manifestBoxSegment), null, undefined, { trustPolicy })
		const init = await validateC2paInitSegment(forgeClaimSignature(vsi.init), { trustPolicy })

		ok(box.result.errorCodes.includes(C2paStatusCode.CLAIM_SIGNATURE_MISMATCH))
		strictEqual(box.result.errorCodes.includes(C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED), false)
		strictEqual(box.result.isTrusted, false)
		ok(init.errorCodes.includes(C2paStatusCode.CLAIM_SIGNATURE_MISMATCH))
		strictEqual(init.isTrusted, false)
	})

	it('leaves isTrusted absent when no session key matches the segment', async () => {
		const trustPolicy = await createTrustPolicy({ trustAnchors: pem('root-ec') })
		const other = await buildVsiInitSegment(signer, signer.chain[0])
		const init = await validateC2paInitSegment(other.init, { trustPolicy })

		const segment = await validateC2paSegment(vsiSegment, init.sessionKeys)

		strictEqual(segment?.result.isValid, false)
		strictEqual('isTrusted' in (segment?.result ?? {}), false)
	})

	it('does not validate a segment against a fabricated trusted session key', async () => {
		const trustPolicy = await createTrustPolicy({ trustAnchors: pem('root-ec') })
		const init = await validateC2paInitSegment(vsi.init, { trustPolicy })
		const impostor = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
		const jwk = await crypto.subtle.exportKey('jwk', impostor.publicKey)
		const fabricated: ValidatedSessionKey = { ...init.sessionKeys[0], jwk: { kty: 'EC', crv: 'P-256', x: jwk.x as string, y: jwk.y as string }, isTrusted: true }

		const segment = await validateC2paSegment(vsiSegment, [fabricated])

		strictEqual(segment?.result.isValid, false)
	})

	it('does not carry trust from one Merkle track to another under the same policy', async () => {
		const trustPolicy = await createTrustPolicy({ trustAnchors: pem('root-ec') })
		const untrusted = await buildMerkleStream(await createTestSigner())

		const trustedInit = await validateC2paInitSegment(merkle.init, { trustPolicy })
		const untrustedInit = await validateC2paInitSegment(untrusted.init, { trustPolicy })

		strictEqual(trustedInit.isTrusted, true)
		strictEqual(untrustedInit.isTrusted, false)
		strictEqual((await validateC2paMerkleSegment(untrusted.segment, untrustedInit.merkleMaps)).result.isTrusted, false)
		strictEqual((await validateC2paMerkleSegment(merkle.segment, trustedInit.merkleMaps)).result.isTrusted, true)
	})

	it('verifies the chain of repeated ManifestBox segments once', async () => {
		const trustPolicy = await createTrustPolicy({ trustAnchors: pem('root-ec') })
		const second = await buildManifestBoxSegment(signer, 2)
		await validateC2paManifestBoxSegment(manifestBoxSegment, null, undefined, { trustPolicy })
		const verify = mock.method(crypto.subtle, 'verify')

		await validateC2paManifestBoxSegment(second, null)
		const withoutPolicy = verify.mock.callCount()
		const validated = await validateC2paManifestBoxSegment(second, null, undefined, { trustPolicy })

		strictEqual(validated.result.isTrusted, true)
		strictEqual(verify.mock.callCount() - withoutPolicy, withoutPolicy)
	})

	it('reports an untrusted init without certificate as not trusted', async () => {
		const trustPolicy = await createTrustPolicy({ trustAnchors: pem('root-ec') })
		const mdatInit = concatBytes(buildInitMediaBoxes(), new Uint8Array([0, 0, 0, 8, 0x6d, 0x64, 0x61, 0x74]))

		const init = await validateC2paInitSegment(mdatInit, { trustPolicy })

		strictEqual(init.isValid, false)
		strictEqual(init.isTrusted, false)
		ok(init.errorCodes.length > 0)
	})
})
