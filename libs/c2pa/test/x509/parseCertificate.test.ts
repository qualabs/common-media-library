import { deepStrictEqual, ok, strictEqual } from 'node:assert'
import { describe, it } from 'node:test'
import { parseCertificate } from '../../src/x509/parseCertificate.ts'
import { extractCertificateSpki } from '../../src/x509/extractCertificateSpki.ts'
import { loadDer } from '../trust/trustFixtures.ts'

const EKU_DOCUMENT_SIGNING = '1.3.6.1.5.5.7.3.36'
const EKU_ANY = '2.5.29.37.0'

describe('parseCertificate', () => {
	it('parses an EC leaf certificate', () => {
		const der = loadDer('leaf-ec')
		const cert = parseCertificate(der)
		ok(cert)
		strictEqual(cert.signatureAlgorithm, '1.2.840.10045.4.3.2')
		strictEqual(cert.signatureAlgorithmParams, null)
		deepStrictEqual(cert.ekuOids, [EKU_DOCUMENT_SIGNING])
		strictEqual(cert.isCa, false)
		strictEqual(cert.keyCertSign, false)
		deepStrictEqual(cert.notBefore, new Date('2025-01-01T00:00:00Z'))
		deepStrictEqual(cert.notAfter, new Date('2099-12-31T23:59:59Z'))
		deepStrictEqual(cert.spki, extractCertificateSpki(der))
		strictEqual(cert.tbsCertificate[0], 0x30)
	})

	it('links issuer and subject by DER bytes', () => {
		const leaf = parseCertificate(loadDer('leaf-ec'))
		const intermediate = parseCertificate(loadDer('intermediate-ec'))
		ok(leaf && intermediate)
		deepStrictEqual(leaf.issuer, intermediate.subject)
	})

	it('reads basic constraints and key usage of a CA', () => {
		const cert = parseCertificate(loadDer('intermediate-ec'))
		ok(cert)
		strictEqual(cert.isCa, true)
		strictEqual(cert.keyCertSign, true)
		deepStrictEqual(cert.ekuOids, [])
	})

	it('reports keyCertSign without cA for a non-CA intermediate', () => {
		const cert = parseCertificate(loadDer('intermediate-ec-no-ca'))
		ok(cert)
		strictEqual(cert.isCa, false)
		strictEqual(cert.keyCertSign, true)
	})

	it('extracts every EKU OID', () => {
		deepStrictEqual(parseCertificate(loadDer('leaf-ec-any-eku'))?.ekuOids, [EKU_DOCUMENT_SIGNING, EKU_ANY])
		deepStrictEqual(parseCertificate(loadDer('leaf-ec-no-eku'))?.ekuOids, [])
	})

	it('parses RSA, RSA-PSS and Ed25519 certificates', () => {
		strictEqual(parseCertificate(loadDer('leaf-rsa'))?.signatureAlgorithm, '1.2.840.113549.1.1.11')
		const pss = parseCertificate(loadDer('leaf-pss'))
		strictEqual(pss?.signatureAlgorithm, '1.2.840.113549.1.1.10')
		ok(pss?.signatureAlgorithmParams)
		strictEqual(parseCertificate(loadDer('leaf-ed25519'))?.signatureAlgorithm, '1.3.101.112')
	})

	it('returns null for malformed input', () => {
		strictEqual(parseCertificate(new Uint8Array(0)), null)
		strictEqual(parseCertificate(new Uint8Array([0x30, 0x03, 0x02, 0x01, 0x01])), null)
		strictEqual(parseCertificate(loadDer('leaf-ec').subarray(0, 100)), null)
	})
})
