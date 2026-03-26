import { decode, encode } from 'cbor-x'
import { findIsoBox, readIsoBoxes } from '@svta/cml-iso-bmff'
import type { C2paAssertion } from '../C2paAssertion.ts'
import { readC2paManifest } from '../readC2paManifest.ts'
import { extractManifestCertificate } from '../extractManifestCertificate.ts'
import { validateBmffHash } from '../bmff/validateBmffHash.ts'
import type { BmffHashExclusion } from '../bmff/BmffHashExclusion.ts'
import { convertCoseKeyToJwk } from '../cose/convertCoseKeyToJwk.ts'
import { verifySignerBinding } from '../cose/verifySignerBinding.ts'
import type { CoseKeyJwk } from '../cose/CoseKeyJwk.ts'
import type { InitSegmentValidation, ValidatedSessionKey } from './InitSegmentValidation.ts'
import { bytesToHex, isKeyExpired } from '../utils.ts'

const BMFF_HASH_ASSERTION_LABEL = 'c2pa.hash.bmff.v3'
const SESSION_KEYS_ASSERTION_LABEL = 'c2pa.session-keys'
const COSE_KEY_ID_LABEL = 2

function normalizeToUint8Array(value: unknown): Uint8Array {
	if (value instanceof Uint8Array) return value
	if (Array.isArray(value)) return new Uint8Array(value as number[])
	const ctor = (value as { constructor?: { name?: string } }).constructor
	if (ctor?.name === 'Tag') return encode(value) as Uint8Array
	throw new Error('Cannot convert value to Uint8Array')
}

function ensureDecodedCbor(value: unknown): unknown {
	if (value instanceof Uint8Array) return decode(value)
	if (Array.isArray(value) && value.length > 0 && typeof (value as number[])[0] === 'number') {
		return decode(new Uint8Array(value as number[]))
	}
	return value
}

function parseCreatedAt(value: unknown): string | null {
	if (typeof value === 'string') return value
	if (value instanceof Date) return value.toISOString()
	if (typeof value === 'object' && value !== null) {
		const obj = value as Record<string, unknown>
		const tagged = obj['@@TAGGED@@']
		if (Array.isArray(tagged) && tagged.length === 2) return String(tagged[1])
		const direct = obj['value'] ?? (obj as unknown as Record<number, unknown>)[1]
		if (typeof direct === 'string') return direct
	}
	return null
}

function extractKidHex(keyData: Record<string, unknown>, coseKey: unknown): string | null {
	const kid = keyData['kid']
	if (kid instanceof Uint8Array) return bytesToHex(kid)
	if (typeof kid === 'string') return kid
	if (Array.isArray(kid) && kid.length > 0) return bytesToHex(new Uint8Array(kid as number[]))

	// Fallback: COSE key field 2 is the key ID per RFC 9052
	const coseKeyLike = coseKey as Map<number, unknown> | Record<number, unknown>
	const coseKid = coseKeyLike instanceof Map ? coseKeyLike.get(COSE_KEY_ID_LABEL) : coseKeyLike[COSE_KEY_ID_LABEL]
	if (coseKid instanceof Uint8Array) return bytesToHex(coseKid)
	if (Array.isArray(coseKid) && coseKid.length > 0) {
		return bytesToHex(new Uint8Array(coseKid as number[]))
	}

	return null
}

function extractKeyArray(data: unknown): unknown[] {
	if (Array.isArray(data)) return data
	if (typeof data === 'object' && data !== null) {
		const obj = data as Record<string, unknown>
		const keys = obj['keys'] ?? obj['sessionKeys']
		if (Array.isArray(keys)) return keys
		if (typeof keys === 'object' && keys !== null) {
			const nested = (keys as Record<string, unknown>)['keys']
			if (Array.isArray(nested)) return nested
		}
	}
	return []
}

async function validateBmffHashAssertion(
	bytes: Uint8Array,
	assertion: C2paAssertion | null,
): Promise<boolean> {
	if (!assertion) return true
	const data = assertion.data as Record<string, unknown>
	const rawHash = data['hash'] ?? data['value']
	if (!rawHash) return true
	const expectedHash =
		rawHash instanceof Uint8Array ? rawHash : new Uint8Array(rawHash as number[])
	let alg = (data['alg'] as string | undefined) ?? 'SHA-256'
	if (alg.toLowerCase() === 'sha256') alg = 'SHA-256'
	const exclusions = (data['exclusions'] as BmffHashExclusion[] | undefined) ?? []
	return validateBmffHash(bytes, expectedHash, { exclusions, alg })
}

async function validateSingleSessionKey(
	entry: unknown,
	certificate: Uint8Array,
): Promise<ValidatedSessionKey | null> {
	const keyData = entry as Record<string, unknown>

	const minSequenceNumber = keyData['minSequenceNumber']
	const validityPeriod = keyData['validityPeriod']
	const createdAt = parseCreatedAt(keyData['createdAt'])

	if (minSequenceNumber == null || !validityPeriod || !createdAt) return null

	const notYetActive = new Date() < new Date(createdAt)
	if (notYetActive || isKeyExpired(createdAt, Number(validityPeriod))) return null

	const coseKey = ensureDecodedCbor(keyData['key'])
	const kid = extractKidHex(keyData, coseKey)
	if (!kid) return null

	const signerBindingRaw = keyData['signerBinding']
	if (!signerBindingRaw) return null

	let signerBindingBytes: Uint8Array
	try {
		signerBindingBytes = normalizeToUint8Array(signerBindingRaw)
	} catch {
		return null
	}

	const bindingValid = await verifySignerBinding(signerBindingBytes, coseKey, certificate)
	if (!bindingValid) return null

	let jwk: CoseKeyJwk
	try {
		jwk = convertCoseKeyToJwk(coseKey)
	} catch {
		return null
	}

	return {
		kid,
		jwk,
		minSequenceNumber: Number(minSequenceNumber),
		validityPeriod: Number(validityPeriod),
		createdAt,
	}
}

async function validateSessionKeys(
	assertion: C2paAssertion,
	certificate: Uint8Array,
): Promise<ValidatedSessionKey[]> {
	const keyEntries = extractKeyArray(ensureDecodedCbor(assertion.data))
	const results = await Promise.all(
		keyEntries.map(entry => validateSingleSessionKey(entry, certificate)),
	)
	return results.filter((key): key is ValidatedSessionKey => key !== null)
}

/**
 * Validates a C2PA init segment: parses the manifest, extracts and verifies
 * the certificate, validates the BMFF hard binding hash, and verifies all
 * session keys from the `c2pa.session-keys` assertion.
 *
 * Only session keys with a valid signer binding and an unexpired validity period
 * are included in the result.
 *
 * @param bytes - Raw init segment bytes (must not contain an `mdat` box)
 * @returns Structured validation result
 * @throws If the bytes contain an `mdat` box, or if no C2PA UUID box is found
 *
 * @example
 * {@includeCode ../../test/init/validateC2paInitSegment.test.ts#example}
 *
 * @public
 */
export async function validateC2paInitSegment(bytes: Uint8Array): Promise<InitSegmentValidation> {
	const boxes = readIsoBoxes(bytes)
	if (findIsoBox(boxes, box => box.type === 'mdat')) {
		throw new Error('Init segment must not contain an mdat box')
	}

	const { activeManifest } = readC2paManifest(bytes)
	const certificate = extractManifestCertificate(bytes)

	const bmffHashAssertion =
		activeManifest.assertions.find(a => a.label === BMFF_HASH_ASSERTION_LABEL) ?? null
	const bmffHashValid = await validateBmffHashAssertion(bytes, bmffHashAssertion)

	const sessionKeysAssertion = activeManifest.assertions.find(
		a => a.label === SESSION_KEYS_ASSERTION_LABEL,
	)
	const sessionKeys =
		sessionKeysAssertion && certificate
			? await validateSessionKeys(sessionKeysAssertion, certificate)
			: []

	return {
		activeManifest,
		certificate,
		manifestId: activeManifest.label,
		bmffHashValid,
		sessionKeys,
	}
}
