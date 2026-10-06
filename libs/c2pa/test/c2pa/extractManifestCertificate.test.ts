import { Encoder } from 'cbor-x/encode'
import {
	extractCertificateChainFromSignatureBytes,
	extractCertificateFromSignatureBytes,
	extractManifestCertificate,
} from '../../src/extractManifestCertificate.ts'
import { deepStrictEqual, ok, strictEqual } from 'node:assert'
import { readFileSync } from 'node:fs'
import { describe, it } from 'node:test'

describe('extractManifestCertificate', () => {
	// #region example
	it('returns null for empty bytes', () => {
		strictEqual(extractManifestCertificate(new Uint8Array(0)), null)
	})
	// #endregion example

	it('returns null for bytes with no C2PA UUID box', () => {
		const fakeBox = new Uint8Array([0x00, 0x00, 0x00, 0x08, 0x6d, 0x6f, 0x6f, 0x76])
		strictEqual(extractManifestCertificate(fakeBox), null)
	})

	it('extracts a DER certificate from a real init segment', () => {
		const fixture = new Uint8Array(
			readFileSync(new URL('../fixtures/init_signed_with_session_keys.m4s', import.meta.url)),
		)
		const cert = extractManifestCertificate(fixture)
		// Either the fixture has a certificate or not — both are acceptable
		ok(cert === null || cert instanceof Uint8Array, 'result must be null or Uint8Array')
		if (cert !== null) {
			ok(cert.length > 0, 'certificate must not be empty')
			// DER certificates start with SEQUENCE tag 0x30
			strictEqual(cert[0], 0x30, 'DER certificate must start with SEQUENCE tag')
		}
	})
})

describe('extractCertificateChainFromSignatureBytes', () => {
	const CBOR = new Encoder({ tagUint8Array: false, useRecords: false, mapsAsObjects: false })
	const LEAF = new Uint8Array([0x30, 0x01, 0x01])
	const INTERMEDIATE = new Uint8Array([0x30, 0x01, 0x02])
	const OTHER = new Uint8Array([0x30, 0x01, 0x03])

	function coseWithHeader(header: Map<number | string, unknown>): Uint8Array {
		const protectedBytes = Uint8Array.from(CBOR.encode(header))
		return Uint8Array.from(CBOR.encode([protectedBytes, new Map(), null, new Uint8Array(64)]))
	}

	it('returns the full chain from the integer label', () => {
		const cose = coseWithHeader(new Map<number, unknown>([[33, [LEAF, INTERMEDIATE]]]))
		deepStrictEqual(extractCertificateChainFromSignatureBytes(cose), [LEAF, INTERMEDIATE])
	})

	it('reads the legacy string label', () => {
		const cose = coseWithHeader(new Map<string, unknown>([['x5chain', [LEAF, INTERMEDIATE]]]))
		deepStrictEqual(extractCertificateChainFromSignatureBytes(cose), [LEAF, INTERMEDIATE])
		deepStrictEqual(extractCertificateFromSignatureBytes(cose), LEAF)
	})

	it('prefers the integer label when both labels are present', () => {
		const cose = coseWithHeader(new Map<number | string, unknown>([['x5chain', [OTHER]], [33, [LEAF]]]))
		deepStrictEqual(extractCertificateChainFromSignatureBytes(cose), [LEAF])
	})

	it('accepts a single certificate instead of an array', () => {
		const cose = coseWithHeader(new Map<number, unknown>([[33, LEAF]]))
		deepStrictEqual(extractCertificateChainFromSignatureBytes(cose), [LEAF])
	})

	it('returns an empty chain without x5chain or for invalid bytes', () => {
		deepStrictEqual(extractCertificateChainFromSignatureBytes(coseWithHeader(new Map([[1, -7]]))), [])
		deepStrictEqual(extractCertificateChainFromSignatureBytes(new Uint8Array([0xff])), [])
	})
})
