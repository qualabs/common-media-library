import { strictEqual } from 'node:assert'
import { describe, it, vi } from 'vite-plus/test'
import { parseCertificate, type ParsedCertificate } from '../../src/x509/parseCertificate.ts'
import {
	isAllowedSignatureAlgorithm,
	verifyCertificateSignature,
} from '../../src/x509/verifyCertificateSignature.ts'
import { loadDer } from '../trust/trustFixtures.ts'

function parse(name: string): ParsedCertificate {
	const cert = parseCertificate(loadDer(name))
	if (!cert) throw new Error(`Cannot parse ${name}`)
	return cert
}

describe('verifyCertificateSignature', () => {
	// #region example
	it('verifies an EC leaf against its intermediate', async () => {
		const leaf = parse('leaf-ec')
		const intermediate = parse('intermediate-ec')
		strictEqual(await verifyCertificateSignature(leaf, intermediate), 'verified')
	})
	// #endregion example

	it('verifies a self-signed EC root against itself', async () => {
		const root = parse('root-ec')
		strictEqual(await verifyCertificateSignature(root, root), 'verified')
	})

	for (const family of ['rsa', 'pss', 'ed25519']) {
		it(`verifies a ${family} leaf against its root`, async () => {
			strictEqual(
				await verifyCertificateSignature(parse(`leaf-${family}`), parse(`root-${family}`)),
				'verified',
			)
		})

		it(`verifies a self-signed ${family} root`, async () => {
			const root = parse(`root-${family}`)
			strictEqual(await verifyCertificateSignature(root, root), 'verified')
		})
	}

	it('rejects a wrong parent key', async () => {
		strictEqual(await verifyCertificateSignature(parse('leaf-ec'), parse('root-ec')), 'failed')
		strictEqual(await verifyCertificateSignature(parse('leaf-rsa'), parse('root-pss')), 'failed')
	})

	it('rejects a tampered tbsCertificate', async () => {
		const leaf = parse('leaf-ec')
		const tampered = leaf.tbsCertificate.slice()
		tampered[tampered.length - 1] ^= 0xff
		strictEqual(
			await verifyCertificateSignature(
				{ ...leaf, tbsCertificate: tampered },
				parse('intermediate-ec'),
			),
			'failed',
		)
	})

	it('reports a signature algorithm that the profile does not allow', async () => {
		const leaf = { ...parse('leaf-ec'), signatureAlgorithm: '1.2.840.113549.1.1.5' }
		strictEqual(await verifyCertificateSignature(leaf, parse('intermediate-ec')), 'disallowed')
		strictEqual(isAllowedSignatureAlgorithm(leaf), false)
		strictEqual(isAllowedSignatureAlgorithm(parse('leaf-ec')), true)
	})

	it('reports ML-DSA as allowed but not supported', async () => {
		const leaf = { ...parse('leaf-ec'), signatureAlgorithm: '2.16.840.1.101.3.4.3.18' }
		strictEqual(isAllowedSignatureAlgorithm(leaf), true)
		strictEqual(await verifyCertificateSignature(leaf, parse('intermediate-ec')), 'unsupported')
	})

	it('reports RSASSA-PSS without maskGenAlgorithm as disallowed', async () => {
		const pss = parse('leaf-pss')
		const hashOnly = Uint8Array.from([
			0x30, 0x0f, 0xa0, 0x0d, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04,
			0x02, 0x01,
		])
		const leaf = { ...pss, signatureAlgorithmParams: hashOnly }
		strictEqual(isAllowedSignatureAlgorithm(leaf), false)
		strictEqual(await verifyCertificateSignature(leaf, parse('root-pss')), 'disallowed')
	})

	it(
		'returns at once for RSASSA-PSS parameters with a negative length',
		{ timeout: 1000 },
		async () => {
			const leaf = {
				...parse('leaf-pss'),
				signatureAlgorithmParams: Uint8Array.from([0x30, 0x06, 0xa0, 0x84, 0xff, 0xff, 0xff, 0xfa]),
			}
			strictEqual(await verifyCertificateSignature(leaf, parse('root-pss')), 'disallowed')
		},
	)

	it('reports a runtime that does not implement the algorithm', async () => {
		const notSupported = Object.assign(new Error('Ed25519'), { name: 'NotSupportedError' })
		const importKey = vi.spyOn(crypto.subtle, 'importKey').mockRejectedValueOnce(notSupported)
		try {
			strictEqual(
				await verifyCertificateSignature(parse('leaf-ed25519'), parse('root-ed25519')),
				'unsupported',
			)
		} finally {
			importKey.mockRestore()
		}
	})
})
