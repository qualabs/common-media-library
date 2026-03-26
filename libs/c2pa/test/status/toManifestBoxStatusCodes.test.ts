import { LiveVideoStatusCode, toManifestBoxStatusCodes } from '@svta/cml-c2pa'
import type { ManifestBoxValidationResult } from '@svta/cml-c2pa'
import { deepStrictEqual } from 'node:assert'
import { describe, it } from 'node:test'

const VALID_RESULT: ManifestBoxValidationResult = {
	manifest: null,
	issuer: null,
	sequenceNumber: 1,
	previousManifestId: null,
	streamId: 'stream-1',
	continuityMethod: 'c2pa.manifestId',
	bmffHashHex: null,
	claimSignatureValid: true,
	hasLiveVideoAssertion: true,
	chainValid: true,
	streamIdValid: true,
	continuityMethodPresent: true,
	sequenceNumberValid: true,
	isValid: true,
}

describe('toManifestBoxStatusCodes', () => {
	// #region example
	it('returns empty array for a fully valid result', () => {
		const codes = toManifestBoxStatusCodes(VALID_RESULT)
		deepStrictEqual(codes, [])
	})
	// #endregion example

	it('returns MANIFEST_INVALID when claim signature fails', () => {
		const codes = toManifestBoxStatusCodes({ ...VALID_RESULT, claimSignatureValid: false, isValid: false })
		deepStrictEqual(codes, [LiveVideoStatusCode.MANIFEST_INVALID])
	})

	it('returns ASSERTION_INVALID when live video assertion is missing', () => {
		const codes = toManifestBoxStatusCodes({ ...VALID_RESULT, hasLiveVideoAssertion: false, isValid: false })
		deepStrictEqual(codes, [LiveVideoStatusCode.ASSERTION_INVALID])
	})

	it('returns ASSERTION_INVALID when streamId does not match', () => {
		const codes = toManifestBoxStatusCodes({ ...VALID_RESULT, streamIdValid: false, isValid: false })
		deepStrictEqual(codes, [LiveVideoStatusCode.ASSERTION_INVALID])
	})

	it('returns ASSERTION_INVALID when sequenceNumber is not increasing', () => {
		const codes = toManifestBoxStatusCodes({ ...VALID_RESULT, sequenceNumberValid: false, isValid: false })
		deepStrictEqual(codes, [LiveVideoStatusCode.ASSERTION_INVALID])
	})

	it('returns CONTINUITY_METHOD_INVALID when continuityMethod is absent', () => {
		const codes = toManifestBoxStatusCodes({ ...VALID_RESULT, continuityMethodPresent: false, isValid: false })
		deepStrictEqual(codes, [LiveVideoStatusCode.CONTINUITY_METHOD_INVALID])
	})

	it('returns CONTINUITY_METHOD_INVALID when chain is broken', () => {
		const codes = toManifestBoxStatusCodes({ ...VALID_RESULT, chainValid: false, isValid: false })
		deepStrictEqual(codes, [LiveVideoStatusCode.CONTINUITY_METHOD_INVALID])
	})

	it('deduplicates ASSERTION_INVALID across multiple failures', () => {
		const codes = toManifestBoxStatusCodes({
			...VALID_RESULT,
			hasLiveVideoAssertion: false,
			streamIdValid: false,
			sequenceNumberValid: false,
			isValid: false,
		})
		deepStrictEqual(codes, [LiveVideoStatusCode.ASSERTION_INVALID])
	})

	it('returns multiple distinct codes for different failure types', () => {
		const codes = toManifestBoxStatusCodes({
			...VALID_RESULT,
			claimSignatureValid: false,
			streamIdValid: false,
			continuityMethodPresent: false,
			isValid: false,
		})
		deepStrictEqual(codes, [
			LiveVideoStatusCode.MANIFEST_INVALID,
			LiveVideoStatusCode.ASSERTION_INVALID,
			LiveVideoStatusCode.CONTINUITY_METHOD_INVALID,
		])
	})
})
