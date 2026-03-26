import { createSequenceState, LiveVideoStatusCode, validateC2paSegment } from '@svta/cml-c2pa'
import { deepStrictEqual, strictEqual } from 'node:assert'
import { describe, it } from 'node:test'

const stubCoseSign1 = {
	protectedBytes: new Uint8Array(0),
	protectedHeader: {},
	unprotectedHeader: {},
	payload: new Uint8Array(0),
	signature: new Uint8Array(0),
	kid: null,
	alg: null,
}

const stubVsiMap = {
	sequenceNumber: 1,
	bmffHash: { hash: new Uint8Array(32), alg: 'SHA-256', exclusions: [] },
	manifestId: new Uint8Array(0),
}

describe('validateC2paSegment', () => {
	// #region example
	it('returns SEGMENT_INVALID when sessionKey is null', async () => {
		const state = createSequenceState()
		const { result, nextSequenceState } = await validateC2paSegment(
			new Uint8Array(0),
			stubCoseSign1,
			stubVsiMap,
			null,
			state,
		)

		strictEqual(result.isValid, false)
		deepStrictEqual(result.errorCodes, [LiveVideoStatusCode.SEGMENT_INVALID])
		strictEqual(nextSequenceState !== state, true)
	})
	// #endregion example

	it('includes sequenceResult in the result', async () => {
		const state = createSequenceState()
		const { result } = await validateC2paSegment(
			new Uint8Array(0),
			stubCoseSign1,
			stubVsiMap,
			null,
			state,
		)

		strictEqual(typeof result.sequenceResult.reason, 'string')
	})

	it('advances the sequence state on each call', async () => {
		let state = createSequenceState()
		;({ nextSequenceState: state } = await validateC2paSegment(
			new Uint8Array(0),
			stubCoseSign1,
			stubVsiMap,
			null,
			state,
		))

		const dupVsi = { ...stubVsiMap, sequenceNumber: 1 }
		const { result } = await validateC2paSegment(
			new Uint8Array(0),
			stubCoseSign1,
			dupVsi,
			null,
			state,
		)

		strictEqual(result.sequenceResult.reason, 'duplicate')
	})
})
