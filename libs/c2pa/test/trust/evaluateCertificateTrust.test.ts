import { strictEqual } from 'node:assert'
import { afterEach, describe, it, vi } from 'vite-plus/test'
import { C2paStatusCode } from '../../src/C2paStatusCode.ts'
import { createTrustPolicy } from '../../src/trust/createTrustPolicy.ts'
import { hashCertificate } from '../../src/trust/evaluateCertificateTrust.ts'
import type { TrustFailure, TrustPolicy } from '../../src/trust/TrustPolicy.ts'
import { VENDOR_EKU_CONFIG, loadDer, pem } from './trustFixtures.ts'

function chain(...names: string[]): Uint8Array[] {
	return names.map(loadDer)
}

function evaluate(policy: TrustPolicy, certs: readonly Uint8Array[]): Promise<TrustFailure | null> {
	return policy.evaluate(certs)
}

function anchors(...names: string[]): Promise<TrustPolicy> {
	return createTrustPolicy({ trustAnchors: names.map(name => pem(name)).join('\n') })
}

const TRUSTED = null
const INVALID = C2paStatusCode.SIGNING_CREDENTIAL_INVALID
const UNTRUSTED = C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED
const OUTSIDE_VALIDITY = C2paStatusCode.CLAIM_SIGNATURE_OUTSIDE_VALIDITY
const UNSUPPORTED = C2paStatusCode.ALGORITHM_UNSUPPORTED

describe('evaluateCertificateTrust', () => {
	afterEach(() => vi.restoreAllMocks())

	// #region example
	it('trusts a leaf that chains to a trust anchor', async () => {
		const policy = await createTrustPolicy({ trustAnchors: pem('root-ec') })
		strictEqual(await evaluate(policy, chain('leaf-ec', 'intermediate-ec')), TRUSTED)
	})
	// #endregion example

	it('trusts a chain that contains the anchor itself', async () => {
		strictEqual(
			await evaluate(await anchors('root-ec'), chain('leaf-ec', 'intermediate-ec', 'root-ec')),
			TRUSTED,
		)
	})

	it('trusts a leaf issued directly by an intermediate anchor', async () => {
		strictEqual(await evaluate(await anchors('intermediate-ec'), chain('leaf-ec')), TRUSTED)
	})

	it('trusts a self-signed leaf listed as an anchor', async () => {
		strictEqual(
			await evaluate(await anchors('self-signed-leaf'), chain('self-signed-leaf')),
			TRUSTED,
		)
	})

	for (const family of ['rsa', 'pss', 'ed25519']) {
		it(`trusts a ${family} chain`, async () => {
			strictEqual(await evaluate(await anchors(`root-${family}`), chain(`leaf-${family}`)), TRUSTED)
		})
	}

	it('does not trust a chain that misses its intermediate', async () => {
		strictEqual(await evaluate(await anchors('root-ec'), chain('leaf-ec')), UNTRUSTED)
	})

	it('rejects a chain out of order, whose first certificate is a CA', async () => {
		strictEqual(
			await evaluate(await anchors('root-ec'), chain('intermediate-ec', 'leaf-ec')),
			INVALID,
		)
	})

	it('does not trust a chain to an anchor with a different key', async () => {
		strictEqual(
			await evaluate(await anchors('root-rsa'), chain('leaf-ec', 'intermediate-ec')),
			UNTRUSTED,
		)
	})

	it('does not trust a leaf whose issuer name matches but whose signature does not', async () => {
		strictEqual(
			await evaluate(await anchors('root-ec'), chain('leaf-ec-forged', 'intermediate-ec')),
			UNTRUSTED,
		)
		strictEqual(
			await evaluate(await anchors('intermediate-ec'), chain('leaf-ec-forged')),
			UNTRUSTED,
		)
	})

	it('does not trust a self-signed leaf that is not an anchor', async () => {
		strictEqual(await evaluate(await anchors('root-ec'), chain('self-signed-leaf')), UNTRUSTED)
	})

	it('does not trust a leaf without EKU', async () => {
		strictEqual(
			await evaluate(await anchors('root-ec'), chain('leaf-ec-no-eku', 'intermediate-ec')),
			INVALID,
		)
	})

	it('does not trust a leaf with anyExtendedKeyUsage', async () => {
		strictEqual(
			await evaluate(await anchors('root-ec'), chain('leaf-ec-any-eku', 'intermediate-ec')),
			INVALID,
		)
	})

	it('reports an expired leaf as outside its validity period', async () => {
		strictEqual(
			await evaluate(await anchors('root-ec'), chain('leaf-ec-expired', 'intermediate-ec')),
			OUTSIDE_VALIDITY,
		)
	})

	it('reports a leaf that is not valid yet as outside its validity period', async () => {
		strictEqual(
			await evaluate(await anchors('root-ec'), chain('leaf-ec-not-yet-valid', 'intermediate-ec')),
			OUTSIDE_VALIDITY,
		)
	})

	it('reports a leaf under an expired intermediate as outside its validity period', async () => {
		strictEqual(
			await evaluate(
				await anchors('root-ec'),
				chain('leaf-under-expired-intermediate', 'intermediate-ec-expired'),
			),
			OUTSIDE_VALIDITY,
		)
	})

	it('does not trust a leaf under an expired anchor', async () => {
		strictEqual(
			await evaluate(
				await anchors('intermediate-ec-expired'),
				chain('leaf-under-expired-intermediate'),
			),
			UNTRUSTED,
		)
	})

	it('does not trust a leaf under an intermediate without a subject key identifier', async () => {
		strictEqual(
			await evaluate(
				await anchors('root-ec'),
				chain('leaf-under-no-ski-intermediate', 'intermediate-ec-no-ski'),
			),
			UNTRUSTED,
		)
	})

	it('does not trust a leaf under an intermediate with critical name constraints', async () => {
		strictEqual(
			await evaluate(
				await anchors('root-ec'),
				chain('leaf-under-name-constrained-intermediate', 'intermediate-ec-name-constraints'),
			),
			UNTRUSTED,
		)
	})

	it('trusts a leaf under an intermediate with a 1024-bit RSA key, as C2PA 2.5 allows', async () => {
		strictEqual(
			await evaluate(
				await anchors('root-rsa'),
				chain('leaf-under-rsa-1024-intermediate', 'intermediate-rsa-1024'),
			),
			TRUSTED,
		)
	})

	it('does not trust a leaf under an intermediate without cA', async () => {
		strictEqual(
			await evaluate(
				await anchors('root-ec'),
				chain('leaf-under-no-ca-intermediate', 'intermediate-ec-no-ca'),
			),
			UNTRUSTED,
		)
	})

	for (const [leaf, defect] of [
		['leaf-ec-ca', 'a leaf with cA and keyCertSign'],
		['leaf-ec-no-digital-signature', 'a leaf without the digitalSignature key usage'],
		['leaf-ec-no-key-usage', 'a leaf without the key usage extension'],
		['leaf-ec-time-stamping', 'a leaf valid for time stamping and another purpose'],
		['leaf-ec-unknown-critical', 'a leaf with an unknown critical extension'],
		['leaf-ec-no-aki', 'a leaf without the authority key identifier'],
		['leaf-secp256k1', 'a leaf with a key on a curve outside the profile'],
	]) {
		it(`does not trust ${defect}`, async () => {
			strictEqual(await evaluate(await anchors('root-ec'), chain(leaf, 'intermediate-ec')), INVALID)
		})
	}

	it('does not trust a leaf with an RSA key shorter than 2048 bits', async () => {
		strictEqual(await evaluate(await anchors('root-rsa'), chain('leaf-rsa-1024')), INVALID)
	})

	it('does not trust a chain that exceeds the path length of an intermediate', async () => {
		strictEqual(
			await evaluate(
				await anchors('root-ec'),
				chain('leaf-under-sub-intermediate', 'sub-intermediate-ec', 'intermediate-ec'),
			),
			UNTRUSTED,
		)
	})

	it('does not trust a chain with a certificate that does not parse', async () => {
		strictEqual(
			await evaluate(await anchors('root-ec'), [loadDer('leaf-ec'), new Uint8Array([0x30, 0x00])]),
			INVALID,
		)
	})

	it('does not trust an empty chain', async () => {
		strictEqual(await evaluate(await anchors('root-ec'), []), UNTRUSTED)
	})

	it('trusts allowed-list entries without EKU or chain checks', async () => {
		const policy = await createTrustPolicy({
			allowedList: [pem('self-signed-leaf'), await hashCertificate(loadDer('leaf-ec-no-eku'))].join(
				'\n',
			),
		})
		strictEqual(await evaluate(policy, chain('self-signed-leaf')), TRUSTED)
		strictEqual(await evaluate(policy, chain('leaf-ec-no-eku')), TRUSTED)
		strictEqual(await evaluate(policy, chain('leaf-ec', 'intermediate-ec')), UNTRUSTED)
	})

	it('checks the validity period of allowed-list entries', async () => {
		const policy = await createTrustPolicy({ allowedList: pem('leaf-ec-expired') })
		strictEqual(await evaluate(policy, chain('leaf-ec-expired')), OUTSIDE_VALIDITY)
	})

	it('does not trust allowed-list entries with a key outside the profile', async () => {
		for (const leaf of ['leaf-rsa-1024', 'leaf-secp256k1']) {
			const policy = await createTrustPolicy({ allowedList: pem(leaf) })
			strictEqual(await evaluate(policy, chain(leaf)), INVALID)
		}
	})

	it('accepts the default EKU set', async () => {
		const policy = await anchors('root-ec')
		strictEqual(await evaluate(policy, chain('leaf-ec-claim-signing', 'intermediate-ec')), TRUSTED)
	})

	it('keeps the default EKU set when the trust config adds EKUs', async () => {
		const policy = await createTrustPolicy({
			trustAnchors: pem('root-ec'),
			trustConfig: VENDOR_EKU_CONFIG,
		})
		strictEqual(await evaluate(policy, chain('leaf-ec-claim-signing', 'intermediate-ec')), TRUSTED)
		strictEqual(await evaluate(policy, chain('leaf-ec', 'intermediate-ec')), TRUSTED)
	})

	it('does not trust a chain longer than 10 certificates', async () => {
		const long = [
			...chain('leaf-ec'),
			...Array.from({ length: 10 }, () => loadDer('intermediate-ec')),
		]
		const digest = vi.spyOn(crypto.subtle, 'digest')
		strictEqual(await evaluate(await anchors('root-ec'), long), UNTRUSTED)
		strictEqual(digest.mock.calls.length, 0)
	})

	it('reports a runtime that cannot verify an algorithm, and does not cache it', async () => {
		const policy = await anchors('root-ed25519')
		const notSupported = Object.assign(new Error('Ed25519'), { name: 'NotSupportedError' })
		const importKey = vi.spyOn(crypto.subtle, 'importKey').mockRejectedValueOnce(notSupported)

		strictEqual(await evaluate(policy, chain('leaf-ed25519')), UNSUPPORTED)
		strictEqual(await evaluate(policy, chain('leaf-ed25519')), TRUSTED)
		strictEqual(importKey.mock.calls.length, 2)
	})

	it('verifies each chain once per policy', async () => {
		const policy = await anchors('root-ec')
		const verify = vi.spyOn(crypto.subtle, 'verify')

		strictEqual(await evaluate(policy, chain('leaf-ec', 'intermediate-ec')), TRUSTED)
		const firstCalls = verify.mock.calls.length
		strictEqual(firstCalls > 0, true)

		strictEqual(await evaluate(policy, chain('leaf-ec', 'intermediate-ec')), TRUSTED)
		strictEqual(verify.mock.calls.length, firstCalls)
	})

	it('compares a cached chain with the validation time at every call', async () => {
		let now = Date.UTC(2024, 0, 1)
		const policy = await createTrustPolicy({
			trustAnchors: pem('root-ec'),
			validationTime: () => new Date(now),
		})
		const certs = chain('leaf-ec', 'intermediate-ec')

		strictEqual(await evaluate(policy, certs), UNTRUSTED)
		now = Date.UTC(2026, 0, 1)
		strictEqual(await evaluate(policy, certs), TRUSTED)
		now = Date.UTC(2100, 0, 1)
		strictEqual(await evaluate(policy, certs), UNTRUSTED)
	})

	it('accepts a clock difference up to the clock tolerance', async () => {
		const oneMinuteEarly = () => new Date(Date.UTC(2098, 0, 1) - 60_000)
		const certs = chain('leaf-ec-not-yet-valid', 'intermediate-ec')
		const strict = await createTrustPolicy({
			trustAnchors: pem('root-ec'),
			validationTime: oneMinuteEarly,
		})
		const tolerant = await createTrustPolicy({
			trustAnchors: pem('root-ec'),
			validationTime: oneMinuteEarly,
			clockTolerance: 120_000,
		})
		strictEqual(await evaluate(strict, certs), OUTSIDE_VALIDITY)
		strictEqual(await evaluate(tolerant, certs), TRUSTED)
	})

	it('moves a cache hit to the end, so the chain in use stays cached', async () => {
		const policy = await anchors('root-ec')
		const verify = vi.spyOn(crypto.subtle, 'verify')
		const inUse = chain('leaf-ec', 'intermediate-ec')
		strictEqual(await evaluate(policy, inUse), TRUSTED)
		for (let i = 0; i < 64; i++) {
			const other = [loadDer('self-signed-leaf').slice(), ...chain('intermediate-ec')]
			other[0][other[0].length - 1] ^= i + 1
			await evaluate(policy, other)
			if (i % 8 === 0) await evaluate(policy, inUse)
		}
		const calls = verify.mock.calls.length
		strictEqual(await evaluate(policy, inUse), TRUSTED)
		strictEqual(verify.mock.calls.length, calls)
	})
})
