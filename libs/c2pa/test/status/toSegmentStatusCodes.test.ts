import { LiveVideoStatusCode, toSegmentStatusCodes } from '@svta/cml-c2pa'
import type { SegmentValidationResult } from '@svta/cml-c2pa'
import { deepStrictEqual } from 'node:assert'
import { describe, it } from 'node:test'

const VALID_RESULT: SegmentValidationResult = {
	keyFound: true,
	signatureValid: true,
	hashValid: true,
	sequenceAboveMin: true,
	keyExpired: false,
	sequenceResult: { isValid: true, reason: 'valid' },
	vsiValid: true,
}

describe('toSegmentStatusCodes', () => {
	// #region example
	it('returns empty array for a fully valid segment', () => {
		const codes = toSegmentStatusCodes(VALID_RESULT)
		deepStrictEqual(codes, [])
	})
	// #endregion example

	it('returns SEGMENT_INVALID when key is not found', () => {
		const codes = toSegmentStatusCodes({ ...VALID_RESULT, keyFound: false, vsiValid: false })
		deepStrictEqual(codes, [LiveVideoStatusCode.SEGMENT_INVALID])
	})

	it('returns SEGMENT_INVALID when signature is invalid', () => {
		const codes = toSegmentStatusCodes({ ...VALID_RESULT, signatureValid: false, vsiValid: false })
		deepStrictEqual(codes, [LiveVideoStatusCode.SEGMENT_INVALID])
	})

	it('returns SEGMENT_INVALID when hash is invalid', () => {
		const codes = toSegmentStatusCodes({ ...VALID_RESULT, hashValid: false, vsiValid: false })
		deepStrictEqual(codes, [LiveVideoStatusCode.SEGMENT_INVALID])
	})

	it('returns SEGMENT_INVALID when sequence is below minimum', () => {
		const codes = toSegmentStatusCodes({ ...VALID_RESULT, sequenceAboveMin: false, vsiValid: false })
		deepStrictEqual(codes, [LiveVideoStatusCode.SEGMENT_INVALID])
	})

	it('returns SESSIONKEY_INVALID when key is expired', () => {
		const codes = toSegmentStatusCodes({ ...VALID_RESULT, keyExpired: true, vsiValid: false })
		deepStrictEqual(codes, [LiveVideoStatusCode.SESSIONKEY_INVALID])
	})

	it('deduplicates SEGMENT_INVALID across multiple failures', () => {
		const codes = toSegmentStatusCodes({
			...VALID_RESULT,
			keyFound: false,
			signatureValid: false,
			hashValid: false,
			vsiValid: false,
		})
		deepStrictEqual(codes, [LiveVideoStatusCode.SEGMENT_INVALID])
	})

	it('returns both SEGMENT_INVALID and SESSIONKEY_INVALID when applicable', () => {
		const codes = toSegmentStatusCodes({
			...VALID_RESULT,
			signatureValid: false,
			keyExpired: true,
			vsiValid: false,
		})
		deepStrictEqual(codes, [
			LiveVideoStatusCode.SEGMENT_INVALID,
			LiveVideoStatusCode.SESSIONKEY_INVALID,
		])
	})
})
