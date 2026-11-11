import { deepStrictEqual, strictEqual } from 'node:assert'
import { describe, it } from 'vite-plus/test'
import { decodeOid, readElement, readLength } from '../../src/x509/asn1.ts'

describe('readLength', () => {
	it('reads the short and the long form', () => {
		deepStrictEqual(readLength(Uint8Array.from([0x05]), 0), { length: 5, bytesRead: 1 })
		deepStrictEqual(readLength(Uint8Array.from([0x81, 0x80, 0]), 0), { length: 128, bytesRead: 2 })
		deepStrictEqual(readLength(Uint8Array.from([0x82, 0x01, 0x00, 0]), 0), {
			length: 256,
			bytesRead: 3,
		})
	})

	it('rejects lengths that DER does not allow', () => {
		strictEqual(readLength(Uint8Array.from([0x80]), 0), null)
		strictEqual(readLength(Uint8Array.from([0x85, 1, 0, 0, 0, 5]), 0), null)
		strictEqual(readLength(Uint8Array.from([0x81, 0x03]), 0), null)
		strictEqual(readLength(Uint8Array.from([0x82, 0x00, 0x90]), 0), null)
		strictEqual(readLength(Uint8Array.from([0x82, 0x01]), 0), null)
	})

	it('reads a 4-byte length as a positive number', () => {
		deepStrictEqual(readLength(Uint8Array.from([0x84, 0x80, 0, 0, 0]), 0), {
			length: 2 ** 31,
			bytesRead: 5,
		})
	})
})

describe('readElement', () => {
	it('rejects a length that runs past the buffer', () => {
		strictEqual(readElement(Uint8Array.from([0x30, 0x84, 0x80, 0, 0, 0]), 0), null)
		strictEqual(readElement(Uint8Array.from([0x30, 0x84, 0xff, 0xff, 0xff, 0xfa]), 0), null)
		strictEqual(readElement(Uint8Array.from([0x30, 0x02, 0x05]), 0), null)
	})

	it('rejects a negative offset', () => {
		strictEqual(readElement(Uint8Array.from([0x30, 0x00]), -2), null)
	})
})

describe('decodeOid', () => {
	it('decodes OIDs', () => {
		strictEqual(
			decodeOid(Uint8Array.from([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x24])),
			'1.3.6.1.5.5.7.3.36',
		)
		strictEqual(decodeOid(Uint8Array.from([0x55, 0x1d, 0x25, 0x00])), '2.5.29.37.0')
	})

	it('decodes a multi-byte first subidentifier', () => {
		strictEqual(decodeOid(Uint8Array.from([0x81, 0x34, 0x03])), '2.100.3')
	})

	it('rejects encodings that DER does not allow', () => {
		strictEqual(
			decodeOid(Uint8Array.from([0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x24, 0x81])),
			'',
		)
		strictEqual(decodeOid(Uint8Array.from([0x2b, 0x80, 0x01])), '')
		strictEqual(decodeOid(new Uint8Array(0)), '')
	})
})
