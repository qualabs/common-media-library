import { strictEqual } from 'node:assert'
import { describe, it } from 'node:test'
import { parseCertificate, type ParsedCertificate } from '../../src/x509/parseCertificate.ts'
import { verifyCertificateSignature } from '../../src/x509/verifyCertificateSignature.ts'
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
		strictEqual(await verifyCertificateSignature(leaf, intermediate), true)
	})
	// #endregion example

	it('verifies a self-signed EC root against itself', async () => {
		const root = parse('root-ec')
		strictEqual(await verifyCertificateSignature(root, root), true)
	})

	for (const family of ['rsa', 'pss', 'ed25519']) {
		it(`verifies a ${family} leaf against its root`, async () => {
			strictEqual(await verifyCertificateSignature(parse(`leaf-${family}`), parse(`root-${family}`)), true)
		})

		it(`verifies a self-signed ${family} root`, async () => {
			const root = parse(`root-${family}`)
			strictEqual(await verifyCertificateSignature(root, root), true)
		})
	}

	it('rejects a wrong parent key', async () => {
		strictEqual(await verifyCertificateSignature(parse('leaf-ec'), parse('root-ec')), false)
		strictEqual(await verifyCertificateSignature(parse('leaf-rsa'), parse('root-pss')), false)
	})

	it('rejects a tampered tbsCertificate', async () => {
		const leaf = parse('leaf-ec')
		const tampered = leaf.tbsCertificate.slice()
		tampered[tampered.length - 1] ^= 0xff
		strictEqual(await verifyCertificateSignature({ ...leaf, tbsCertificate: tampered }, parse('intermediate-ec')), false)
	})

	it('rejects an unsupported signature algorithm', async () => {
		const leaf = parse('leaf-ec')
		strictEqual(await verifyCertificateSignature({ ...leaf, signatureAlgorithm: '1.2.840.113549.1.1.5' }, parse('intermediate-ec')), false)
	})
})
