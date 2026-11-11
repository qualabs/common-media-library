import { C2paStatusCode, createTrustPolicy } from '@svta/cml-c2pa'
import { ok, rejects, strictEqual } from 'node:assert'
import { describe, it } from 'vite-plus/test'
import { hashCertificate } from '../../src/trust/evaluateCertificateTrust.ts'
import { loadDer, pem } from './trustFixtures.ts'

const CLAIM_SIGNING_LEAF = ['leaf-ec-claim-signing', 'intermediate-ec']

describe('createTrustPolicy', () => {
	// #region example
	it('creates a policy from PEM trust anchors', async () => {
		const trustAnchors = pem('root-ec')
		const policy = await createTrustPolicy({ trustAnchors })

		strictEqual(await policy.evaluate([loadDer('leaf-ec'), loadDer('intermediate-ec')]), null)
	})
	// #endregion example

	it('rejects options without trustAnchors and allowedList', async () => {
		await rejects(createTrustPolicy({}), /options need trustAnchors, allowedList, or both/)
		await rejects(createTrustPolicy({ trustConfig: '1.2.3.4' }), /options need trustAnchors/)
	})

	it('rejects a URL or a path instead of content', async () => {
		await rejects(
			createTrustPolicy({ trustAnchors: 'https://example.com/anchors.pem' }),
			/trustAnchors: no PEM certificate found\. Pass the text of the source/,
		)
		await rejects(
			createTrustPolicy({ allowedList: '/etc/c2pa/allowed.pem' }),
			/allowedList: line 1 is not a PEM certificate or a base64 SHA-256 hash/,
		)
	})

	it('rejects a source without entries', async () => {
		await rejects(
			createTrustPolicy({ allowedList: '# comment only\n' }),
			/allowedList: no PEM certificate or hash found/,
		)
	})

	it('lists every failure in one error', async () => {
		const notCertificate = '-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n'
		await rejects(
			createTrustPolicy({
				trustAnchors: `${pem('root-ec')}\n${notCertificate}`,
				allowedList: `${pem('leaf-ec')}\nnot-a-hash\n`,
				trustConfig: '1.3.6.1.4.1.99999.1\nnot.an.oid\n',
			}),
			{
				message:
					'createTrustPolicy: trustAnchors: PEM certificate 2 does not parse. ' +
					`allowedList: line ${pem('leaf-ec').split('\n').length + 1} is not a PEM certificate or a base64 SHA-256 hash. ` +
					'trustConfig: line 2 is not an OID',
			},
		)
	})

	it('rejects a PEM block that is not base64', async () => {
		await rejects(
			createTrustPolicy({
				trustAnchors: `${pem('root-ec')}\n-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n`,
			}),
			/trustAnchors: a PEM certificate block has no END line/,
		)
	})

	it('reads hashes with comments and CRLF line breaks', async () => {
		const hash = await hashCertificate(loadDer('self-signed-leaf'))
		const policy = await createTrustPolicy({
			allowedList: `# Allowed signers\r\n// c2pa-rs comment\r\n${hash} # self-signed test leaf\r\n`,
		})
		strictEqual(await policy.evaluate([loadDer('self-signed-leaf')]), null)
	})

	it('adds trustConfig EKUs to the default EKUs', async () => {
		const policy = await createTrustPolicy({
			trustAnchors: pem('root-ec'),
			trustConfig: '// vendor EKU\n1.3.6.1.4.1.99999.1\n',
		})
		strictEqual(await policy.evaluate(CLAIM_SIGNING_LEAF.map(loadDer)), null)
		strictEqual(await policy.evaluate([loadDer('leaf-ec'), loadDer('intermediate-ec')]), null)
	})

	it('does not trust a chain that fails, so a load error never reaches a validator', async () => {
		const policy = await createTrustPolicy({ trustAnchors: pem('root-rsa') })
		strictEqual(
			await policy.evaluate(CLAIM_SIGNING_LEAF.map(loadDer)),
			C2paStatusCode.SIGNING_CREDENTIAL_UNTRUSTED,
		)
	})

	it('returns an immutable policy', async () => {
		const policy = await createTrustPolicy({ trustAnchors: pem('root-ec') })
		ok(Object.isFrozen(policy))
	})
})
