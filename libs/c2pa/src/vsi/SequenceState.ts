/**
 * State and result types for monotonic sequence number validation
 * per C2PA Live Streaming Specification §18.4.
 *
 * @public
 */

/**
 * Immutable state snapshot for a single stream's sequence number history.
 *
 * Pass to {@link validateSequenceNumber} and store the returned `nextState`
 * to advance the stream forward. Construct the initial state with
 * {@link createSequenceState}.
 *
 * @public
 */
export type SequenceState = {
	readonly lastSequenceNumber: number | null
	readonly seenSequences: ReadonlySet<number>
}

/**
 * Result of validating a single sequence number against the current stream state.
 *
 * Discriminated on `reason` — narrow to `'gap_detected'` to access
 * `missingFrom` / `missingTo`.
 *
 * @public
 */
export type SequenceValidationResult =
	| { readonly isValid: true; readonly reason: 'valid' }
	| {
			readonly isValid: false
			readonly reason: 'sequence_number_below_minimum' | 'duplicate' | 'out_of_order'
		}
	| {
			readonly isValid: false
			readonly reason: 'gap_detected'
			readonly missingFrom: number
			readonly missingTo: number
		}
