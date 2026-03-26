import { LiveVideoStatusCode, toInitStatusCodes } from '@svta/cml-c2pa'
import type { InitSegmentValidation } from '@svta/cml-c2pa'
import { deepStrictEqual } from 'node:assert'
import { describe, it } from 'node:test'

const VALID_RESULT: InitSegmentValidation = {
	activeManifest: {
		label: 'test-manifest',
		assertions: [],
		signatureInfo: null,
		instanceId: null,
	},
	certificate: null,
	manifestId: 'test-manifest',
	bmffHashValid: true,
	sessionKeys: [
		{
			kid: 'key-1',
			jwk: { kty: 'EC', crv: 'P-256', x: '', y: '' },
			minSequenceNumber: 0,
			validityPeriod: 3600,
			createdAt: new Date().toISOString(),
		},
	],
}

describe('toInitStatusCodes', () => {
	// #region example
	it('returns empty array for a valid init segment', () => {
		const codes = toInitStatusCodes(VALID_RESULT)
		deepStrictEqual(codes, [])
	})
	// #endregion example

	it('returns INIT_INVALID when bmff hash fails', () => {
		const codes = toInitStatusCodes({ ...VALID_RESULT, bmffHashValid: false })
		deepStrictEqual(codes, [LiveVideoStatusCode.INIT_INVALID])
	})

	it('returns SESSIONKEY_INVALID when no session keys are valid', () => {
		const codes = toInitStatusCodes({ ...VALID_RESULT, sessionKeys: [] })
		deepStrictEqual(codes, [LiveVideoStatusCode.SESSIONKEY_INVALID])
	})

	it('returns both codes when hash fails and no session keys', () => {
		const codes = toInitStatusCodes({ ...VALID_RESULT, bmffHashValid: false, sessionKeys: [] })
		deepStrictEqual(codes, [
			LiveVideoStatusCode.INIT_INVALID,
			LiveVideoStatusCode.SESSIONKEY_INVALID,
		])
	})
})
