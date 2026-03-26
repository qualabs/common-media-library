import type { SequenceValidationResult } from '../vsi/SequenceState.ts'

/**
 * The result of validating a single C2PA live stream segment.
 *
 * Returned by {@link validateC2paSegment}.
 *
 * @public
 */
export type SegmentValidationResult = {
  readonly keyFound: boolean
  readonly signatureValid: boolean
  readonly hashValid: boolean
  readonly sequenceAboveMin: boolean
  readonly keyExpired: boolean
  readonly sequenceResult: SequenceValidationResult
  readonly vsiValid: boolean
}
