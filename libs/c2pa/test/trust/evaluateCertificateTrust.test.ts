import { strictEqual } from 'node:assert'
import { afterEach, describe, it, mock } from 'node:test'
import { C2paStatusCode } from '../../src/C2paStatusCode.ts'
import { createTrustPolicy } from '../../src/trust/createTrustPolicy.ts'
import { evaluateCertificateTrust } from '../../src/trust/evaluateCertificateTrust.ts'
import type { TrustPolicy } from '../../src/trust/TrustPolicy.ts'
import { allowedListFixture, CLAIM_SIGNING_ONLY_CONFIG, loadDer, pem } from './trustFixtures.ts'

function chain(...names: string[]): Uint8Array[] {
	return names.map(loadDer)
}

function anchors(...names: string[]): Promise<TrustPolicy> {
	return createTrustPolicy({ trustAnchors: names.map(name => pem(name)).join('\n') })
}

const TRUSTED = null
const INVALID = C2paStatusCode.SIGNING_CREDENTIAL_INVALID
const UNTRUSTED = C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED

describe('evaluateCertificateTrust', () => {
	afterEach(() => mock.restoreAll())

	// #region example
	it('trusts a leaf that chains to a trust anchor', async () => {
		const policy = await createTrustPolicy({ trustAnchors: pem('root-ec') })
		strictEqual(await evaluateCertificateTrust(policy, chain('leaf-ec', 'intermediate-ec')), TRUSTED)
	})
	// #endregion example

	it('trusts a chain that contains the anchor itself', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('root-ec'), chain('leaf-ec', 'intermediate-ec', 'root-ec')), TRUSTED)
	})

	it('trusts a leaf issued directly by an intermediate anchor', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('intermediate-ec'), chain('leaf-ec')), TRUSTED)
	})

	it('trusts a self-signed leaf listed as an anchor', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('self-signed-leaf'), chain('self-signed-leaf')), TRUSTED)
	})

	for (const family of ['rsa', 'pss', 'ed25519']) {
		it(`trusts a ${family} chain`, async () => {
			strictEqual(await evaluateCertificateTrust(await anchors(`root-${family}`), chain(`leaf-${family}`)), TRUSTED)
		})
	}

	it('does not trust a chain that misses its intermediate', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('root-ec'), chain('leaf-ec')), UNTRUSTED)
	})

	it('rejects a chain out of order, whose first certificate is a CA', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('root-ec'), chain('intermediate-ec', 'leaf-ec')), INVALID)
	})

	it('does not trust a chain to an anchor with a different key', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('root-rsa'), chain('leaf-ec', 'intermediate-ec')), UNTRUSTED)
	})

	it('does not trust a leaf whose issuer name matches but whose signature does not', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('root-ec'), chain('leaf-ec-forged', 'intermediate-ec')), UNTRUSTED)
		strictEqual(await evaluateCertificateTrust(await anchors('intermediate-ec'), chain('leaf-ec-forged')), UNTRUSTED)
	})

	it('does not trust a self-signed leaf that is not an anchor', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('root-ec'), chain('self-signed-leaf')), UNTRUSTED)
	})

	it('does not trust a leaf without EKU', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('root-ec'), chain('leaf-ec-no-eku', 'intermediate-ec')), INVALID)
	})

	it('does not trust a leaf with anyExtendedKeyUsage', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('root-ec'), chain('leaf-ec-any-eku', 'intermediate-ec')), INVALID)
	})

	it('does not trust an expired leaf on the anchor path', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('root-ec'), chain('leaf-ec-expired', 'intermediate-ec')), UNTRUSTED)
	})

	it('does not trust a leaf under an expired intermediate', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('root-ec'), chain('leaf-under-expired-intermediate', 'intermediate-ec-expired')), UNTRUSTED)
	})

	it('does not trust a leaf under an expired anchor', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('intermediate-ec-expired'), chain('leaf-under-expired-intermediate')), UNTRUSTED)
	})

	it('does not trust a leaf under an intermediate without cA', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('root-ec'), chain('leaf-under-no-ca-intermediate', 'intermediate-ec-no-ca')), UNTRUSTED)
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
			strictEqual(await evaluateCertificateTrust(await anchors('root-ec'), chain(leaf, 'intermediate-ec')), INVALID)
		})
	}

	it('does not trust a leaf with an RSA key shorter than 2048 bits', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('root-rsa'), chain('leaf-rsa-1024')), INVALID)
	})

	it('does not trust a chain that exceeds the path length of an intermediate', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('root-ec'), chain('leaf-under-sub-intermediate', 'sub-intermediate-ec', 'intermediate-ec')), UNTRUSTED)
	})

	it('does not trust a chain with a certificate that does not parse', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('root-ec'), [loadDer('leaf-ec'), new Uint8Array([0x30, 0x00])]), INVALID)
	})

	it('does not trust an empty chain', async () => {
		strictEqual(await evaluateCertificateTrust(await anchors('root-ec'), []), UNTRUSTED)
	})

	it('trusts allowed-list entries without EKU or validity checks', async () => {
		const policy = await createTrustPolicy({ allowedList: await allowedListFixture() })
		strictEqual(await evaluateCertificateTrust(policy, chain('self-signed-leaf')), TRUSTED)
		strictEqual(await evaluateCertificateTrust(policy, chain('leaf-ec-expired', 'intermediate-ec')), TRUSTED)
		strictEqual(await evaluateCertificateTrust(policy, chain('leaf-ec', 'intermediate-ec')), UNTRUSTED)
	})

	it('does not trust allowed-list entries with a key outside the profile', async () => {
		for (const leaf of ['leaf-rsa-1024', 'leaf-secp256k1']) {
			const policy = await createTrustPolicy({ allowedList: pem(leaf) })
			strictEqual(await evaluateCertificateTrust(policy, chain(leaf)), INVALID)
		}
	})

	it('accepts the default EKU set', async () => {
		const policy = await anchors('root-ec')
		strictEqual(await evaluateCertificateTrust(policy, chain('leaf-ec-claim-signing', 'intermediate-ec')), TRUSTED)
	})

	it('replaces the default EKU set with the trust config', async () => {
		const policy = await createTrustPolicy({
			trustAnchors: pem('root-ec'),
			trustConfig: CLAIM_SIGNING_ONLY_CONFIG,
		})
		strictEqual(await evaluateCertificateTrust(policy, chain('leaf-ec-claim-signing', 'intermediate-ec')), TRUSTED)
		strictEqual(await evaluateCertificateTrust(policy, chain('leaf-ec', 'intermediate-ec')), INVALID)
	})

	it('does not trust anything when a source failed to load', async () => {
		const policy = await createTrustPolicy({
			trustAnchors: pem('root-ec'),
			allowedList: 'no entries\n',
		})
		strictEqual(await evaluateCertificateTrust(policy, chain('leaf-ec', 'intermediate-ec')), UNTRUSTED)
	})

	it('does not trust anything with a policy that has no sources', async () => {
		strictEqual(await evaluateCertificateTrust(await createTrustPolicy(), chain('self-signed-leaf')), UNTRUSTED)
	})

	it('does not trust anything with a policy built by hand', async () => {
		strictEqual(await evaluateCertificateTrust({ loadErrors: [] }, chain('leaf-ec', 'intermediate-ec')), UNTRUSTED)
	})

	it('verifies each chain once per policy', async () => {
		const policy = await anchors('root-ec')
		const verify = mock.method(crypto.subtle, 'verify')

		strictEqual(await evaluateCertificateTrust(policy, chain('leaf-ec', 'intermediate-ec')), TRUSTED)
		const firstCalls = verify.mock.callCount()
		strictEqual(firstCalls > 0, true)

		strictEqual(await evaluateCertificateTrust(policy, chain('leaf-ec', 'intermediate-ec')), TRUSTED)
		strictEqual(verify.mock.callCount(), firstCalls)
	})

	it('checks the validity period of a cached chain at every call', async () => {
		const policy = await anchors('root-ec')
		mock.timers.enable({ apis: ['Date'], now: Date.UTC(2024, 0, 1) })

		strictEqual(await evaluateCertificateTrust(policy, chain('leaf-ec', 'intermediate-ec')), UNTRUSTED)
		mock.timers.setTime(Date.UTC(2026, 0, 1))
		strictEqual(await evaluateCertificateTrust(policy, chain('leaf-ec', 'intermediate-ec')), TRUSTED)
		mock.timers.setTime(Date.UTC(2100, 0, 1))
		strictEqual(await evaluateCertificateTrust(policy, chain('leaf-ec', 'intermediate-ec')), UNTRUSTED)

		mock.timers.reset()
	})
})
