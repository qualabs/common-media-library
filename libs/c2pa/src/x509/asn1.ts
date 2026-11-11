/**
 * Minimal ASN.1 DER parsing helpers for X.509 certificate navigation.
 *
 * @internal
 */

export const ASN1_TAG_BOOLEAN = 0x01
export const ASN1_TAG_INTEGER = 0x02
export const ASN1_TAG_BIT_STRING = 0x03
export const ASN1_TAG_OCTET_STRING = 0x04
export const ASN1_TAG_OBJECT_IDENTIFIER = 0x06
export const ASN1_TAG_SEQUENCE = 0x30
export const ASN1_TAG_SET = 0x31
export const ASN1_TAG_UTC_TIME = 0x17
export const ASN1_TAG_GENERALIZED_TIME = 0x18
export const ASN1_TAG_CONTEXT_0 = 0xa0
export const ASN1_TAG_CONTEXT_3 = 0xa3
const ASN1_LONG_FORM_FLAG = 0x80
const ASN1_LONG_FORM_MASK = 0x7f

export type Asn1Element = {
	readonly tag: number
	readonly value: Uint8Array
	readonly totalSize: number
}

const ASN1_MAX_LENGTH_BYTES = 4
const BYTE_RANGE = 256

/**
 * Reads a DER length. Returns `null` for the indefinite form, a long form that is not minimal,
 * more than 4 length bytes, or a length that runs past the end of `bytes`.
 *
 * @internal
 */
export function readLength(
	bytes: Uint8Array,
	offset: number,
): { length: number; bytesRead: number } | null {
	if (offset >= bytes.length) return null
	const first = bytes[offset]
	if (first < ASN1_LONG_FORM_FLAG) return { length: first, bytesRead: 1 }
	const count = first & ASN1_LONG_FORM_MASK
	if (count === 0 || count > ASN1_MAX_LENGTH_BYTES || offset + count >= bytes.length) return null
	if (bytes[offset + 1] === 0) return null
	let length = 0
	for (let i = 1; i <= count; i++) length = length * BYTE_RANGE + bytes[offset + i]
	if (length < ASN1_LONG_FORM_FLAG) return null
	return { length, bytesRead: 1 + count }
}

export function readElement(bytes: Uint8Array, offset: number): Asn1Element | null {
	if (offset < 0 || offset + 2 > bytes.length) return null
	const tag = bytes[offset]
	const header = readLength(bytes, offset + 1)
	if (!header) return null
	const headerSize = 1 + header.bytesRead
	const valueEnd = offset + headerSize + header.length
	if (valueEnd > bytes.length) return null
	return {
		tag,
		value: bytes.subarray(offset + headerSize, valueEnd),
		totalSize: headerSize + header.length,
	}
}

/**
 * Reads an ASN.1 element and returns its full DER encoding (tag + length + value).
 *
 * @internal
 */
export function readElementRaw(bytes: Uint8Array, offset: number): Uint8Array | null {
	const el = readElement(bytes, offset)
	if (!el) return null
	return bytes.subarray(offset, offset + el.totalSize)
}

/**
 * Reads the value bytes of a non-negative INTEGER as a number.
 *
 * @internal
 */
export function readUnsigned(value: Uint8Array): number {
	return value.reduce((n, byte) => n * 256 + byte, 0)
}

/**
 * Decodes the value bytes of an OBJECT IDENTIFIER to dotted-decimal form.
 * Returns an empty string for an encoding that DER does not allow.
 *
 * @internal
 */
export function decodeOid(value: Uint8Array): string {
	const subidentifiers: number[] = []
	let current = 0
	let started = false
	for (const byte of value) {
		if (!started && byte === ASN1_LONG_FORM_FLAG) return ''
		started = true
		current = current * 128 + (byte & ASN1_LONG_FORM_MASK)
		if ((byte & ASN1_LONG_FORM_FLAG) === 0) {
			subidentifiers.push(current)
			current = 0
			started = false
		}
	}
	if (started || subidentifiers.length === 0) return ''
	const [first, ...rest] = subidentifiers
	const arcs = first < 80 ? [Math.floor(first / 40), first % 40] : [2, first - 80]
	return [...arcs, ...rest].join('.')
}
