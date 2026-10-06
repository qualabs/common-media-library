import { createTrustPolicy } from '@svta/cml-c2pa'
import { deepStrictEqual, match, ok, strictEqual, throws } from 'node:assert'
import { afterEach, describe, it, mock } from 'node:test'
import { pem, PKI_PATH } from './trustFixtures.ts'

function stubFetch(status: number, body: string = ''): void {
	mock.method(globalThis, 'fetch', async () => new Response(body, { status }))
}

describe('createTrustPolicy', () => {
	afterEach(() => mock.restoreAll())

	// #region example
	it('creates a policy from inline PEM trust anchors', async () => {
		const trustAnchors = pem('root-ec')
		const policy = await createTrustPolicy({ trustAnchors })

		deepStrictEqual(policy.loadErrors, [])
	})
	// #endregion example

	it('creates a policy without any source', async () => {
		deepStrictEqual((await createTrustPolicy()).loadErrors, [])
		deepStrictEqual((await createTrustPolicy({})).loadErrors, [])
	})

	it('loads a source from a URL', async () => {
		stubFetch(200, pem('root-ec'))
		const policy = await createTrustPolicy({ trustAnchors: 'https://example.com/anchors.pem' })
		deepStrictEqual(policy.loadErrors, [])
	})

	it('reports a URL that answers with an error status', async () => {
		stubFetch(404)
		const policy = await createTrustPolicy({ trustAnchors: 'https://example.com/anchors.pem' })
		strictEqual(policy.loadErrors.length, 1)
		match(policy.loadErrors[0], /^trustAnchors: .*"https:\/\/example\.com\/anchors\.pem".*HTTP 404/)
	})

	it('reports a URL that cannot be fetched', async () => {
		mock.method(globalThis, 'fetch', async () => {
			throw new TypeError('fetch failed')
		})
		const policy = await createTrustPolicy({ allowedList: 'http://example.com/allowed.txt' })
		match(policy.loadErrors[0], /^allowedList: .*fetch failed/)
	})

	it('loads a source from a local path', async () => {
		const policy = await createTrustPolicy({
			trustAnchors: PKI_PATH,
			allowedList: PKI_PATH,
		})
		deepStrictEqual(policy.loadErrors, [])
	})

	it('reports a missing local file', async () => {
		const policy = await createTrustPolicy({ trustConfig: `${PKI_PATH}.missing` })
		match(policy.loadErrors[0], /^trustConfig: .*pki\.pem\.missing.*ENOENT/)
	})

	it('reports a source without usable entries', async () => {
		const policy = await createTrustPolicy({
			trustAnchors: 'no certificates here\n',
			allowedList: 'not-a-hash\n',
			trustConfig: '# comment only\n',
		})
		deepStrictEqual(policy.loadErrors, [
			'trustAnchors: cannot use inline content: no usable entries',
			'allowedList: cannot use inline content: no usable entries',
			'trustConfig: cannot use inline content: no usable entries',
		])
	})

	it('reports a certificate block that does not parse', async () => {
		const badBase64 = '-----BEGIN CERTIFICATE-----\n!!!\n-----END CERTIFICATE-----\n'
		const notCertificate = '-----BEGIN CERTIFICATE-----\nMAA=\n-----END CERTIFICATE-----\n'
		const policy = await createTrustPolicy({
			trustAnchors: `${pem('root-ec')}\n${badBase64}`,
			allowedList: `${pem('leaf-ec')}\n${notCertificate}`,
		})
		deepStrictEqual(policy.loadErrors, [
			'trustAnchors: cannot use inline content: certificate 2 does not parse',
			'allowedList: cannot use inline content: certificate 2 does not parse',
		])
	})

	it('reports only the failed source', async () => {
		stubFetch(500)
		const policy = await createTrustPolicy({
			trustAnchors: pem('root-ec'),
			allowedList: 'https://example.com/allowed.txt',
		})
		strictEqual(policy.loadErrors.length, 1)
		match(policy.loadErrors[0], /^allowedList: /)
	})

	it('returns an immutable policy', async () => {
		const policy = await createTrustPolicy({ trustConfig: 'not.an.oid\n' })
		ok(Object.isFrozen(policy))
		throws(() => (policy.loadErrors as string[]).push('x'))
	})
})
